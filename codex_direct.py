#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""codex-direct — 在终端里用 ChatGPT/Codex 订阅直接调用 GPT-5.6。

授权走 OpenAI 官方的 Codex device-code 流程（终端打印链接 + 设备码，浏览器里确认），
调用走 ChatGPT 后端的 Responses 接口，全程不使用按量计费的 API Key，也不依赖
任何本地网关。只用标准库，没有第三方依赖。

    codex_direct.py login
    codex_direct.py chat "帮我看看这段代码"
    codex_direct.py -i
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import stat
import sys
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager, suppress
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple
from urllib import error as urlerror, parse as urlparse, request as urlrequest

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows has no flock
    fcntl = None

# --- OpenAI Codex 的 OAuth / 调用端点 ---------------------------------------
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
DEVICE_USERCODE_URL = "https://auth.openai.com/api/accounts/deviceauth/usercode"
DEVICE_TOKEN_URL = "https://auth.openai.com/api/accounts/deviceauth/token"
DEVICE_VERIFICATION_URL = "https://auth.openai.com/codex/device"
DEVICE_REDIRECT_URI = "https://auth.openai.com/deviceauth/callback"
OAUTH_TOKEN_URL = "https://auth.openai.com/oauth/token"
RESPONSES_URL = "https://chatgpt.com/backend-api/codex/responses"

# Codex CLI 的身份标识；ChatGPT 后端按这个识别客户端，不要随意改。
ORIGINATOR = "codex-tui"
USER_AGENT = "codex-tui/0.146.0 (Mac OS 26.5.0; arm64) iTerm.app/3.6.10 (codex-tui; 0.146.0)"

DEVICE_POLL_TIMEOUT = 15 * 60
DEFAULT_POLL_INTERVAL = 5
REFRESH_SKEW = 120  # access_token 剩余不足这么多秒就提前刷新

DEFAULT_MODEL = "gpt-5.6-terra"
KNOWN_MODELS = [
    "gpt-5.6-terra",
    "gpt-5.6-sol",
    "gpt-5.6-luna",
    "gpt-5.5",
    "gpt-5.4",
    "gpt-5.4-mini",
    "gpt-5.3-codex-spark",
]
EFFORTS = ["none", "low", "medium", "high"]

AUTH_PATH = os.path.expanduser(
    os.environ.get("CODEX_DIRECT_AUTH_FILE", "~/.codex-direct/auth.json")
)


class CodexError(RuntimeError):
    """带上下文的失败，main() 负责渲染成一行人话。"""


# --- 小工具 -----------------------------------------------------------------


def _post(url: str, *, json_body: Any = None, form: Any = None,
          headers: Optional[Dict[str, str]] = None, timeout: int = 60):
    """POST 并返回 (status, body_bytes)；HTTP 错误不抛异常，交给调用方判断。"""
    if json_body is not None:
        payload = json.dumps(json_body).encode()
        content_type = "application/json"
    else:
        payload = urlparse.urlencode(form or {}).encode()
        content_type = "application/x-www-form-urlencoded"

    req = urlrequest.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", content_type)
    req.add_header("Accept", "application/json")
    # 必须覆盖默认的 Python-urllib/x.y：auth.openai.com 前面的 Cloudflare 见到它
    # 会直接回 530 cf_route_error。
    req.add_header("User-Agent", USER_AGENT)
    for key, value in (headers or {}).items():
        req.add_header(key, value)

    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urlerror.HTTPError as exc:
        return exc.code, exc.read()
    except urlerror.URLError as exc:
        raise CodexError(f"网络请求失败 ({url}): {exc.reason}") from exc
    except (TimeoutError, OSError) as exc:
        raise CodexError(f"网络请求失败 ({url}): {exc}") from exc


def _decode_json(raw: bytes, context: str) -> Dict[str, Any]:
    """Decode an object response and turn malformed payloads into CLI errors."""
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        preview = raw.decode(errors="replace")[:200]
        raise CodexError(f"{context}返回了无效 JSON: {preview}") from exc
    if not isinstance(payload, dict):
        raise CodexError(f"{context}返回格式错误（需要 JSON 对象）")
    return payload


def _decode_jwt_claims(token: str) -> Dict[str, Any]:
    """只读 payload，不验签——签名由 OpenAI 侧负责，这里只取展示/路由字段。"""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


# --- 凭证存取 ---------------------------------------------------------------


# OpenAI rotates the refresh token on every refresh: the old one dies the moment
# a new pair is issued. Two concurrent refreshes therefore invalidate each other
# and force a re-login, so every refresh serializes on one lock per auth file —
# a thread lock for this process, an flock for the other terminals/scripts
# sharing ~/.codex-direct/auth.json.
_AUTH_LOCKS_GUARD = threading.Lock()
_AUTH_LOCKS: Dict[str, threading.Lock] = {}


@contextmanager
def auth_lock(path: str) -> Iterator[None]:
    """Hold the exclusive refresh lock for ``path`` across threads and processes."""
    resolved = os.path.abspath(os.path.expanduser(path))
    directory = os.path.dirname(resolved) or "."
    with suppress(OSError):
        os.makedirs(directory, mode=stat.S_IRWXU, exist_ok=True)

    with _AUTH_LOCKS_GUARD:
        thread_lock = _AUTH_LOCKS.setdefault(resolved, threading.Lock())

    with thread_lock:
        if fcntl is None:
            yield
            return
        try:
            fd = os.open(
                f"{resolved}.lock",
                os.O_CREAT | os.O_RDWR,
                stat.S_IRUSR | stat.S_IWUSR,
            )
        except OSError as exc:
            raise CodexError(f"无法创建凭证锁（{resolved}.lock）: {exc}") from exc
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            with suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def load_auth(path: str = AUTH_PATH) -> Dict[str, Any]:
    if not os.path.exists(path):
        raise CodexError(f"还没有授权凭证（{path}）。先跑一次：codex_direct.py login")
    try:
        with open(path, encoding="utf-8") as handle:
            auth = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CodexError(f"无法读取授权凭证（{path}）: {exc}") from exc
    if not isinstance(auth, dict):
        raise CodexError(f"授权凭证格式错误（{path}）：需要 JSON 对象")
    return auth


def save_auth(auth: Dict[str, Any], path: str = AUTH_PATH) -> None:
    """凭证等同于账号访问权，原子写入并将文件权限设为 0600。"""
    directory = os.path.dirname(path) or "."
    fd = -1
    tmp = ""
    try:
        if not os.path.exists(directory):
            os.makedirs(directory, mode=stat.S_IRWXU, exist_ok=True)
            os.chmod(directory, stat.S_IRWXU)

        # 不 chmod 已存在的任意父目录：--auth-file ./auth.json 不应把当前项目
        # 目录悄悄改成 0700。临时文件放在同目录，确保 os.replace 原子生效。
        fd, tmp = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", dir=directory)
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            json.dump(auth, handle, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except Exception as exc:
        if fd >= 0:
            os.close(fd)
        if tmp:
            with suppress(FileNotFoundError):
                os.unlink(tmp)
        if isinstance(exc, OSError):
            raise CodexError(f"无法写入授权凭证（{path}）: {exc}") from exc
        raise


def _auth_from_token_response(body: Dict[str, Any],
                              previous: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    access_token = body.get("access_token", "")
    claims = _decode_jwt_claims(access_token)
    id_claims = _decode_jwt_claims(body.get("id_token", "")) if body.get("id_token") else {}
    auth_info = id_claims.get("https://api.openai.com/auth", {})

    # access_token 自带的 exp 最准；拿不到就退回 expires_in。
    expires_at = claims.get("exp")
    if not expires_at:
        try:
            expires_at = time.time() + float(body.get("expires_in") or 3600)
        except (TypeError, ValueError) as exc:
            raise CodexError("token 响应里的 expires_in 无效") from exc

    previous = previous or {}
    return {
        "type": "codex",
        "access_token": access_token,
        # 刷新响应里不一定回传 refresh_token，缺了就沿用旧的。
        "refresh_token": body.get("refresh_token") or previous.get("refresh_token", ""),
        "id_token": body.get("id_token") or previous.get("id_token", ""),
        "account_id": auth_info.get("chatgpt_account_id") or previous.get("account_id", ""),
        "plan_type": auth_info.get("chatgpt_plan_type") or previous.get("plan_type", ""),
        "email": id_claims.get("email") or previous.get("email", ""),
        "expires_at": float(expires_at),
        "last_refresh": _iso(time.time()),
    }


# --- 授权：device code 流程 --------------------------------------------------


def device_login(path: str = AUTH_PATH) -> Dict[str, Any]:
    status, raw = _post(DEVICE_USERCODE_URL, json_body={"client_id": CLIENT_ID})
    if status != 200:
        raise CodexError(f"申请设备码失败 (HTTP {status}): {raw.decode(errors='replace')[:300]}")

    payload = _decode_json(raw, "设备码接口")
    device_auth_id = payload.get("device_auth_id", "").strip()
    user_code = (payload.get("user_code") or payload.get("usercode") or "").strip()
    if not device_auth_id or not user_code:
        raise CodexError(f"设备码响应缺字段: {payload}")

    try:
        interval = max(1, int(str(payload.get("interval") or DEFAULT_POLL_INTERVAL)))
    except ValueError:
        interval = DEFAULT_POLL_INTERVAL

    print()
    print("  在浏览器里打开：\033[4m%s\033[0m" % DEVICE_VERIFICATION_URL)
    print("  输入设备码：    \033[1m%s\033[0m" % user_code)
    print()
    print("  等待授权中，完成后本终端会自动继续（Ctrl-C 取消）…", flush=True)

    token_payload = _poll_device_token(device_auth_id, user_code, interval)

    auth_code = token_payload.get("authorization_code", "").strip()
    verifier = token_payload.get("code_verifier", "").strip()
    if not auth_code or not verifier:
        raise CodexError(f"设备授权响应缺字段: {list(token_payload)}")

    # 注意：PKCE 的 verifier 是服务端下发的，不是本地生成的——这点和标准
    # RFC 8628 设备流不一样，按标准写会在这一步失败。
    status, raw = _post(OAUTH_TOKEN_URL, form={
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code": auth_code,
        "redirect_uri": DEVICE_REDIRECT_URI,
        "code_verifier": verifier,
    })
    if status != 200:
        raise CodexError(f"换取 token 失败 (HTTP {status}): {raw.decode(errors='replace')[:300]}")

    auth = _auth_from_token_response(_decode_json(raw, "token 接口"))
    if not auth["access_token"]:
        raise CodexError("token 响应里没有 access_token")
    if not auth["account_id"]:
        raise CodexError("token 响应里没有 ChatGPT account_id")
    save_auth(auth, path)
    return auth


def _poll_device_token(device_auth_id: str, user_code: str, interval: int) -> Dict[str, Any]:
    deadline = time.time() + DEVICE_POLL_TIMEOUT
    body = {"device_auth_id": device_auth_id, "user_code": user_code}

    while True:
        if time.time() > deadline:
            raise CodexError("等待授权超时（15 分钟）")

        status, raw = _post(DEVICE_TOKEN_URL, json_body=body)
        if 200 <= status < 300:
            return _decode_json(raw, "设备授权接口")
        # 403 / 404 通常表示“用户还没点确认”。如果服务端明确返回拒绝
        # 或过期，就立即结束，而不是让用户无意义地等满 15 分钟。
        if status in (403, 404):
            try:
                pending = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                pending = {}
            error_code = str(pending.get("error") or "") if isinstance(pending, dict) else ""
            if error_code in {"access_denied", "expired_token", "authorization_declined"}:
                raise CodexError(f"设备授权失败: {error_code}")
            time.sleep(interval)
            continue
        raise CodexError(f"轮询授权状态失败 (HTTP {status}): {raw.decode(errors='replace')[:300]}")


# --- token 刷新 --------------------------------------------------------------


def refresh_auth(auth: Dict[str, Any], path: str = AUTH_PATH) -> Dict[str, Any]:
    """Refresh the access token, serialized against other terminals/threads.

    Another holder of the lock may already have refreshed while we waited, so the
    on-disk credential is re-read first and reused when it is usable — spending
    our (now stale) refresh token on top of theirs would invalidate both.
    """
    with auth_lock(path):
        latest = _latest_auth(auth, path)
        if latest.get("access_token") != auth.get("access_token") and _is_fresh(latest):
            return latest
        return _refresh_auth_unlocked(latest, path)


def _is_fresh(auth: Dict[str, Any]) -> bool:
    try:
        expires_at = float(auth.get("expires_at") or 0)
    except (TypeError, ValueError):
        return False
    return bool(auth.get("access_token")) and expires_at - time.time() > REFRESH_SKEW


def _latest_auth(auth: Dict[str, Any], path: str) -> Dict[str, Any]:
    """Re-read the credential file, falling back to the in-memory copy."""
    try:
        return load_auth(path)
    except CodexError:
        return auth


def _refresh_auth_unlocked(auth: Dict[str, Any], path: str) -> Dict[str, Any]:
    refresh_token = auth.get("refresh_token", "").strip()
    if not refresh_token:
        raise CodexError("凭证里没有 refresh_token，需要重新 login")

    status, raw = _post(OAUTH_TOKEN_URL, form={
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "refresh_token": refresh_token,
        "scope": "openid profile email",
    })
    if status != 200:
        raise CodexError(
            f"刷新 token 失败 (HTTP {status})，可能需要重新 login: "
            f"{raw.decode(errors='replace')[:300]}"
        )

    refreshed = _auth_from_token_response(
        _decode_json(raw, "token 刷新接口"), previous=auth
    )
    if not refreshed["access_token"]:
        raise CodexError("刷新响应里没有 access_token，需要重新 login")
    if not refreshed["account_id"]:
        raise CodexError("刷新后缺少 ChatGPT account_id，需要重新 login")
    save_auth(refreshed, path)
    return refreshed


def ensure_fresh(auth: Dict[str, Any], path: str = AUTH_PATH) -> Dict[str, Any]:
    if _is_fresh(auth):
        return auth
    with auth_lock(path):
        latest = _latest_auth(auth, path)
        if _is_fresh(latest):
            return latest
        return _refresh_auth_unlocked(latest, path)


# --- 调用 --------------------------------------------------------------------


def build_input(history: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    """把 (role, text) 历史转成 Responses 接口的 input 结构。"""
    items = []
    for turn in history:
        is_user = turn["role"] == "user"
        items.append({
            "type": "message",
            "role": turn["role"],
            "content": [{
                "type": "input_text" if is_user else "output_text",
                "text": turn["text"],
            }],
        })
    return items


def stream_response(auth: Dict[str, Any], history: List[Dict[str, str]], *,
                    model: str, effort: str, instructions: str,
                    session_id: str) -> Iterator[Tuple[str, Any]]:
    """向 ChatGPT 后端发一轮请求，产出 ('delta'|'reasoning'|'done', payload)。"""
    body = {
        "model": model,
        "instructions": instructions,
        "input": build_input(history),
        # 这个端点只接受流式，非流式会被拒；--no-stream 只是不逐字打印。
        "stream": True,
        "store": False,
    }
    if effort != "none":
        body["reasoning"] = {"effort": effort, "summary": "auto"}

    req = urlrequest.Request(RESPONSES_URL, data=json.dumps(body).encode(), method="POST")
    req.add_header("Authorization", "Bearer " + auth["access_token"])
    req.add_header("Chatgpt-Account-Id", auth.get("account_id", ""))
    req.add_header("Originator", ORIGINATOR)
    req.add_header("User-Agent", USER_AGENT)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "text/event-stream")
    req.add_header("Session-Id", session_id)

    try:
        resp = urlrequest.urlopen(req, timeout=600)
    except urlerror.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:400]
        if exc.code == 401:
            raise _Unauthorized(detail) from exc
        if exc.code == 429:
            raise CodexError(f"订阅额度受限 (HTTP 429): {detail}") from exc
        raise CodexError(f"调用失败 (HTTP {exc.code}): {detail}") from exc
    except urlerror.URLError as exc:
        raise CodexError(f"网络请求失败: {exc.reason}") from exc
    except (TimeoutError, OSError) as exc:
        raise CodexError(f"网络请求失败: {exc}") from exc

    with resp:
        for line in resp:
            line = line.decode("utf-8", errors="replace").rstrip("\r\n")
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if not data or data == "[DONE]":
                continue
            try:
                event = json.loads(data)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue

            kind = event.get("type", "")
            if kind == "response.output_text.delta":
                yield "delta", event.get("delta", "")
            elif kind == "response.reasoning_summary_text.delta":
                yield "reasoning", event.get("delta", "")
            elif kind == "response.completed":
                yield "done", event.get("response", {})
            elif kind in ("response.failed", "error"):
                response_error = (event.get("response") or {}).get("error") or {}
                event_error = event.get("error") or {}
                message = (
                    response_error.get("message")
                    if isinstance(response_error, dict) else str(response_error)
                ) or (
                    event_error.get("message")
                    if isinstance(event_error, dict) else str(event_error)
                ) or event.get("message") or json.dumps(event)[:300]
                raise CodexError(f"模型返回失败: {message}")


class _Unauthorized(CodexError):
    """access_token 失效，值得刷新后重试一次。"""


def ask(auth: Dict[str, Any], history: List[Dict[str, str]], *, model: str, effort: str,
        instructions: str, session_id: str, show_stream: bool, show_reasoning: bool,
        path: str = AUTH_PATH) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
    """跑完一轮，返回 (回答文本, usage, 可能已刷新的 auth)。401 会自动刷新重试一次。"""
    for attempt in (1, 2):
        chunks: List[str] = []
        usage: Dict[str, Any] = {}
        reasoning_open = False
        try:
            for kind, payload in stream_response(
                auth, history, model=model, effort=effort,
                instructions=instructions, session_id=session_id,
            ):
                if kind == "reasoning":
                    if show_reasoning:
                        if not reasoning_open:
                            sys.stderr.write("\033[2m")
                            reasoning_open = True
                        sys.stderr.write(payload)
                        sys.stderr.flush()
                elif kind == "delta":
                    if reasoning_open:
                        sys.stderr.write("\033[0m\n")
                        sys.stderr.flush()
                        reasoning_open = False
                    chunks.append(payload)
                    if show_stream:
                        sys.stdout.write(payload)
                        sys.stdout.flush()
                elif kind == "done":
                    usage = payload.get("usage", {}) or {}
            if reasoning_open:
                sys.stderr.write("\033[0m\n")
                sys.stderr.flush()
                reasoning_open = False
            return "".join(chunks), usage, auth
        except _Unauthorized as exc:
            if attempt == 2:
                raise CodexError("access_token 刷新后仍被拒绝，请重新 login") from exc
            auth = refresh_auth(auth, path)
        finally:
            # A stream can fail after opening the dim reasoning style. Always
            # restore the terminal before an error is rendered or a retry starts.
            if reasoning_open:
                sys.stderr.write("\033[0m\n")
                sys.stderr.flush()
    raise CodexError("unreachable")


# --- 子命令 ------------------------------------------------------------------


def cmd_login(args) -> int:
    auth = device_login(args.auth_file)
    print()
    print("  \033[32m授权成功\033[0m  %s（%s）" % (auth["email"], auth["plan_type"]))
    print("  凭证已写入 %s" % args.auth_file)
    return 0


def cmd_status(args) -> int:
    auth = load_auth(args.auth_file)
    remaining = float(auth.get("expires_at") or 0) - time.time()
    id_claims = _decode_jwt_claims(auth.get("id_token", ""))
    sub_until = id_claims.get("https://api.openai.com/auth", {}).get(
        "chatgpt_subscription_active_until"
    )

    print("  账号      %s" % auth.get("email", "-"))
    print("  套餐      %s" % auth.get("plan_type", "-"))
    print("  account   %s" % auth.get("account_id", "-"))
    print("  凭证文件  %s" % args.auth_file)
    if remaining > 0:
        print("  token     有效，%d 分钟后过期（到期自动刷新）" % (remaining / 60))
    else:
        print("  token     已过期，下次调用时自动刷新")
    if sub_until:
        print("  订阅至    %s" % sub_until)
    return 0


def cmd_models(args) -> int:
    print("  已知可用模型（默认 %s）：" % DEFAULT_MODEL)
    for name in KNOWN_MODELS:
        print("    %s" % name)
    print()
    print("  模型清单由 OpenAI 侧决定，这里是实测可用的一组；换新型号直接 --model 传即可。")
    return 0


def _read_prompt(args) -> str:
    parts = list(args.prompt or [])
    if not parts or parts == ["-"]:
        if sys.stdin.isatty() and not parts:
            raise CodexError(
                "没有输入内容。用法：codex_direct.py chat \"你的问题\"，或用管道喂给它"
            )
        return sys.stdin.read().strip()
    text = " ".join(parts)
    # 有管道输入时自动拼在问题后面，方便
    # `cat foo.py | codex_direct.py chat "解释一下"`。
    if not sys.stdin.isatty():
        piped = sys.stdin.read().strip()
        if piped:
            text = f"{text}\n\n{piped}"
    return text


def cmd_chat(args) -> int:
    auth = ensure_fresh(load_auth(args.auth_file), args.auth_file)
    prompt = _read_prompt(args)
    if not prompt:
        raise CodexError("输入为空")

    session_id = str(uuid.uuid4())
    history = [{"role": "user", "text": prompt}]
    stream = not args.no_stream and not args.json

    text, usage, _ = ask(
        auth, history, model=args.model, effort=args.effort,
        instructions=args.system, session_id=session_id,
        show_stream=stream, show_reasoning=args.reasoning,
        path=args.auth_file,
    )

    if args.json:
        print(json.dumps({"model": args.model, "text": text, "usage": usage},
                         ensure_ascii=False, indent=2))
    else:
        if stream:
            print()
        else:
            print(text)
        sys.stdout.flush()
        if args.usage:
            sys.stderr.write("\033[2m[%s] in=%s out=%s total=%s\033[0m\n" % (
                args.model, usage.get("input_tokens", "?"),
                usage.get("output_tokens", "?"), usage.get("total_tokens", "?"),
            ))
    return 0


def cmd_repl(args) -> int:
    auth = ensure_fresh(load_auth(args.auth_file), args.auth_file)
    session_id = str(uuid.uuid4())
    history: List[Dict[str, str]] = []

    print("  codex-direct · %s · %s（%s）" % (args.model, auth.get("email", "-"),
                                              auth.get("plan_type", "-")))
    print("  /model <名字> 换模型 · /effort <%s> · /reset 清空上下文 · Ctrl-D 退出" %
          "|".join(EFFORTS))
    model, effort = args.model, args.effort

    while True:
        try:
            line = input("\n\033[1m›\033[0m ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not line:
            continue

        if line.startswith("/"):
            command, _, argument = line[1:].partition(" ")
            argument = argument.strip()
            if command in ("quit", "exit"):
                return 0
            if command == "reset":
                history.clear()
                session_id = str(uuid.uuid4())
                print("  上下文已清空")
            elif command == "model" and argument:
                model = argument
                print("  模型 → %s" % model)
            elif command == "effort" and argument in EFFORTS:
                effort = argument
                print("  推理档位 → %s" % effort)
            else:
                print("  可用命令：/model /effort /reset /quit")
            continue

        history.append({"role": "user", "text": line})
        print()
        try:
            text, usage, auth = ask(
                auth, history, model=model, effort=effort,
                instructions=args.system, session_id=session_id,
                show_stream=True, show_reasoning=args.reasoning,
                path=args.auth_file,
            )
        except CodexError as exc:
            history.pop()
            print("\n  \033[31m%s\033[0m" % exc)
            continue

        history.append({"role": "assistant", "text": text})
        print()
        if args.usage:
            sys.stderr.write("\033[2m[%s] in=%s out=%s\033[0m\n" % (
                model, usage.get("input_tokens", "?"), usage.get("output_tokens", "?")))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codex_direct.py",
        description="用 ChatGPT/Codex 订阅的 OAuth 授权，在终端直接调用 GPT-5.6",
    )
    parser.add_argument("--auth-file", default=AUTH_PATH,
                        help="凭证路径（默认 %(default)s）")
    sub = parser.add_subparsers(dest="command")

    login = sub.add_parser("login", help="走 device-code 流程完成授权")
    login.set_defaults(func=cmd_login)

    status = sub.add_parser("status", help="查看当前账号、套餐和 token 状态")
    status.set_defaults(func=cmd_status)

    models = sub.add_parser("models", help="列出已知可用模型")
    models.set_defaults(func=cmd_models)

    def add_call_options(target, with_prompt: bool):
        if with_prompt:
            target.add_argument("prompt", nargs="*", help="问题内容；留空或传 - 从 stdin 读")
        target.add_argument("-m", "--model", default=DEFAULT_MODEL,
                            help="模型（默认 %(default)s）")
        target.add_argument("-e", "--effort", default="medium", choices=EFFORTS,
                            help="推理档位（默认 %(default)s）")
        target.add_argument("-s", "--system", default="",
                            help="系统指令 instructions")
        target.add_argument("-r", "--reasoning", action="store_true",
                            help="把推理摘要打到 stderr")
        target.add_argument("-u", "--usage", action="store_true",
                            help="结束后打印 token 用量")

    chat = sub.add_parser("chat", help="问一次就退出")
    add_call_options(chat, with_prompt=True)
    chat.add_argument("--no-stream", action="store_true", help="等全部生成完再一次性输出")
    chat.add_argument("--json", action="store_true", help="输出 JSON（含 usage）")
    chat.set_defaults(func=cmd_chat)

    repl = sub.add_parser("repl", help="多轮对话")
    add_call_options(repl, with_prompt=False)
    repl.set_defaults(func=cmd_repl)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # 裸跑 `codex_direct.py -i` 的交互模式简写。
    if argv and argv[0] in ("-i", "--interactive"):
        argv[0] = "repl"
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        return 1

    args.auth_file = os.path.expanduser(args.auth_file)
    try:
        return args.func(args)
    except CodexError as exc:
        sys.stderr.write("\n  \033[31m%s\033[0m\n" % exc)
        return 1
    except KeyboardInterrupt:
        sys.stderr.write("\n  已取消\n")
        return 130


if __name__ == "__main__":
    sys.exit(main())

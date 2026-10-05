# codex-direct

在终端里用 ChatGPT/Codex 订阅直接调用 GPT模型。授权走 OpenAI 官方的 Codex
device-code 流程（终端打印链接 + 设备码，浏览器确认），调用走 ChatGPT 后端的
Responses 接口。

**不用按量计费的 API Key，也不经过 cli-proxy-api 网关**——单文件、零第三方依赖。

## 用法

```bash
./codex_direct.py login                      # 首次授权：打印设备码，浏览器确认
./codex_direct.py status                     # 账号 / 套餐 / token 有效期
./codex_direct.py models                     # 已知可用模型

./codex_direct.py chat "一句话解释隐含波动率"
./codex_direct.py chat -m gpt-5.6-sol -e high "..."   # 换模型 / 提高推理档位
./codex_direct.py chat --json "2+2=?"                 # JSON 输出（含 usage）
cat foo.py | ./codex_direct.py chat "这段代码在干嘛"    # 管道输入

./codex_direct.py -i                         # 多轮对话（= repl）
```

repl 里：`/model <名字>` 换模型、`/effort none|low|medium|high`、`/reset` 清上下文、
Ctrl-D 退出。

常用参数：`-e/--effort` 推理档位、`-r/--reasoning` 把推理摘要打到 stderr、
`-u/--usage` 打印 token 用量、`-s/--system` 系统指令。

## 凭证

默认存 `~/.codex-direct/auth.json`（目录 0700 / 文件 0600），可用 `--auth-file` 或
`CODEX_DIRECT_AUTH_FILE` 改。access_token 到期前 120 秒自动用 refresh_token 续期，
调用中拿到 401 也会刷新后重试一次。

这份凭证和 `apps/cli-proxy-api/auths/` 里那份是**各自独立的登录**。刻意不共用：
refresh_token 有可能在刷新时轮换，两个进程读写同一份会互相踢掉登录态。

## 协议要点

授权（`auth.openai.com`）：

1. `POST /api/accounts/deviceauth/usercode` `{client_id}` → `device_auth_id` + `user_code`
2. 用户在 `https://auth.openai.com/codex/device` 输入 `user_code`
3. 轮询 `POST /api/accounts/deviceauth/token`：403/404 = 等待中；2xx → `authorization_code` + `code_verifier`
4. `POST /oauth/token` `grant_type=authorization_code`，`redirect_uri=https://auth.openai.com/deviceauth/callback`
5. 续期：同端点 `grant_type=refresh_token`，`scope="openid profile email"`
6. `id_token` 的 JWT claim 里取 `chatgpt_account_id` / `chatgpt_plan_type`

第 3 步反常规：**PKCE 的 code_verifier 是服务端下发的**，不是客户端生成，按
RFC 8628 标准设备流来写会失败。

调用（`chatgpt.com/backend-api/codex/responses`）：Responses 协议，强制
`stream: true`，必需 header 是 `Authorization` / `Chatgpt-Account-Id` /
`Originator: codex-tui` / codex 的 `User-Agent`。

**所有请求都必须显式设 User-Agent**：Cloudflare 见到默认的 `Python-urllib/x.y`
会直接回 530 `cf_route_error`。TLS 指纹倒是不用伪装，标准库能过。

协议是 OpenAI 的私有接口，会随 codex CLI 版本漂移；出现 400/403 时先对一下
`User-Agent` 里的版本号和模型名。

from __future__ import annotations

import io
import json
import os
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import codex_direct as cd


class AuthStorageTests(unittest.TestCase):
    def test_save_is_atomic_secure_and_does_not_chmod_existing_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "shared"
            directory.mkdir(mode=0o755)
            os.chmod(directory, 0o755)
            path = directory / "auth.json"

            cd.save_auth({"access_token": "secret"}, str(path))

            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(json.loads(path.read_text()), {"access_token": "secret"})
            self.assertEqual(list(directory.glob(".auth.json.*")), [])

    def test_load_reports_corrupt_json_without_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "auth.json"
            path.write_text("{not-json", encoding="utf-8")
            with self.assertRaisesRegex(cd.CodexError, "无法读取授权凭证"):
                cd.load_auth(str(path))


class RefreshLockTests(unittest.TestCase):
    """A rotating refresh token dies the moment a newer pair is issued."""

    @staticmethod
    def _stored(path, access, expires_at):
        Path(path).write_text(
            json.dumps({
                "access_token": access,
                "refresh_token": f"refresh-for-{access}",
                "account_id": "acct",
                "expires_at": expires_at,
            }),
            encoding="utf-8",
        )

    def test_ensure_fresh_reuses_a_refresh_another_process_already_did(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "auth.json")
            # On disk: already refreshed by someone else. In hand: the stale copy.
            self._stored(path, "new-access", time.time() + 3600)
            stale = {
                "access_token": "old-access",
                "refresh_token": "old-refresh",
                "account_id": "acct",
                "expires_at": time.time() - 10,
            }

            with mock.patch.object(cd, "_post") as post:
                refreshed = cd.ensure_fresh(stale, path)

            post.assert_not_called()
            self.assertEqual(refreshed["access_token"], "new-access")

    def test_refresh_after_401_reuses_a_newer_credential_instead_of_rotating_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "auth.json")
            self._stored(path, "new-access", time.time() + 3600)
            stale = {
                "access_token": "old-access",
                "refresh_token": "old-refresh",
                "account_id": "acct",
                "expires_at": time.time() + 3600,
            }

            with mock.patch.object(cd, "_post") as post:
                refreshed = cd.refresh_auth(stale, path)

            post.assert_not_called()
            self.assertEqual(refreshed["access_token"], "new-access")

    def test_concurrent_expiry_triggers_exactly_one_token_rotation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "auth.json")
            expired = time.time() - 10
            self._stored(path, "old-access", expired)
            calls = []
            barrier = threading.Barrier(4)

            def fake_post(url, **kwargs):
                calls.append(kwargs.get("form", {}).get("refresh_token"))
                # Hold the lock long enough that an unserialized implementation
                # would let a second caller in with the same refresh token.
                time.sleep(0.05)
                return 200, json.dumps({
                    "access_token": f"fresh-{len(calls)}",
                    "refresh_token": f"rotated-{len(calls)}",
                    "expires_in": 3600,
                }).encode()

            def worker(results, index):
                barrier.wait()
                results[index] = cd.ensure_fresh(cd.load_auth(path), path)

            results = [None] * 4
            with (
                mock.patch.object(cd, "_post", fake_post),
                mock.patch.object(cd, "_decode_jwt_claims", return_value={
                    "https://api.openai.com/auth": {"chatgpt_account_id": "acct"},
                }),
            ):
                threads = [
                    threading.Thread(target=worker, args=(results, i)) for i in range(4)
                ]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()

            self.assertEqual(calls, ["refresh-for-old-access"])
            self.assertTrue(all(r and r["access_token"] == "fresh-1" for r in results), results)

    def test_lock_file_is_owner_only_and_beside_the_credential(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "auth.json")
            with cd.auth_lock(path):
                lock = Path(f"{path}.lock")
                self.assertTrue(lock.exists())
                self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)


class RefreshTests(unittest.TestCase):
    def test_missing_access_token_does_not_overwrite_working_credentials(self):
        auth = {
            "access_token": "old-access",
            "refresh_token": "refresh",
            "account_id": "acct",
            "expires_at": time.time() - 10,
        }
        with (
            mock.patch.object(cd, "_post", return_value=(200, b'{"expires_in":3600}')),
            mock.patch.object(cd, "save_auth") as save,
            self.assertRaisesRegex(cd.CodexError, "没有 access_token"),
        ):
            cd._refresh_auth_unlocked(auth, "/tmp/unused-auth.json")
        save.assert_not_called()


class TerminalResetTests(unittest.TestCase):
    def test_reasoning_style_is_reset_when_stream_fails(self):
        def broken_stream(*args, **kwargs):
            yield "reasoning", "thinking"
            raise cd.CodexError("boom")

        stderr = io.StringIO()
        with (
            mock.patch.object(cd, "stream_response", broken_stream),
            mock.patch.object(cd.sys, "stderr", stderr),
            self.assertRaisesRegex(cd.CodexError, "boom"),
        ):
            cd.ask(
                {"access_token": "x"},
                [{"role": "user", "text": "hi"}],
                model="gpt-test",
                effort="high",
                instructions="",
                session_id="session",
                show_stream=False,
                show_reasoning=True,
            )

        self.assertTrue(stderr.getvalue().endswith("\033[0m\n"))


if __name__ == "__main__":
    unittest.main()

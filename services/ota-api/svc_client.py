#!/usr/bin/env python3
"""
调用 signing-service 的客户端：HMAC-SM3 服务身份 + 发布授权票据。

签名串（与签名服务逐字节一致）：
    METHOD \n path?query \n timestamp \n nonce \n SM3(body)

身份密钥从文件读取（0600），不进环境变量、不进日志。
"""
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path


def sm3_hex(data: bytes) -> str:
    h = hashlib.new("sm3")
    h.update(data)
    return h.hexdigest()


class SigningClient:
    def __init__(self, base_url, service_id, secret_file):
        self.base_url = base_url.rstrip("/")
        self.service_id = service_id
        self.secret_file = Path(secret_file)

    def _secret(self):
        return self.secret_file.read_text().strip().encode()

    def request(self, method, path, body=None, timeout=60):
        body = body or b""
        ts = str(int(time.time()))
        nonce = uuid.uuid4().hex
        canonical = "\n".join([
            method.upper(), path, ts, nonce, sm3_hex(body),
        ]).encode()
        sig = hmac.new(self._secret(), canonical, "sm3").hexdigest()

        req = urllib.request.Request(
            f"{self.base_url}{path}", data=body if method != "GET" else None,
            headers={
                "X-OTA-Service": self.service_id,
                "X-OTA-Timestamp": ts,
                "X-OTA-Nonce": nonce,
                "X-OTA-Signature": sig,
                "Content-Type": "application/json",
            },
            method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            raw = e.read().decode(errors="ignore")
            try:
                payload = json.loads(raw)
            except ValueError:
                payload = {"error": raw[:500]}
            return e.code, payload
        except Exception as e:
            return 502, {"error": f"signing service unreachable: {e}"}

    def post_json(self, path, obj, timeout=60):
        return self.request("POST", path,
                            json.dumps(obj, separators=(",", ":")).encode(),
                            timeout=timeout)

    def get_json(self, path, timeout=30):
        return self.request("GET", path, timeout=timeout)


def admin_token():
    """管理接口令牌：只用于 /admin/* 这类状态变更接口。"""
    path = Path(os.environ.get("ADMIN_TOKEN_FILE",
                               "/keys/service-auth/admin.token"))
    try:
        return path.read_text().strip()
    except OSError:
        return ""

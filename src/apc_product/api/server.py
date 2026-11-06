from __future__ import annotations

import hmac
import json
import os
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from ..service import APCService
from ..store import IdempotencyConflictError
from ..version import VERSION

MAX_BODY = 1_000_000


def _control_free(value: str) -> bool:
    return not any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def _has_unicode_surrogate(value) -> bool:
    """Reject JSON strings containing UTF-16 surrogate code points.

    JSON parsers may accept escaped surrogate halves; they are not valid Unicode
    scalar values and can break UTF-8 response serialization or storage layers.
    """
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if any(0xD800 <= ord(ch) <= 0xDFFF for ch in item):
                return True
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return False


class Handler(BaseHTTPRequestHandler):
    service = APCService()
    server_version = "APCProduct"
    sys_version = ""

    def version_string(self):
        return self.server_version

    def log_message(self, fmt, *args):
        # Do not log the query string; it is a future-proofing measure against
        # tenant identifiers or sensitive material being placed in URLs.
        path = urlparse(self.path).path
        safe = path.encode("ascii", "backslashreplace").decode("ascii")
        code = args[1] if len(args) > 1 else "-"
        sys.stderr.write(f"{self.client_address[0]} {self.command} {safe} {code}\n")

    def _send(self, code, obj, *, headers=None):
        raw = json.dumps(obj, ensure_ascii=True, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Vary", "Authorization")
        if os.getenv("APC_ASSUME_TLS", "0") == "1":
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def _auth(self):
        expected = os.getenv("APC_ADMIN_TOKEN")
        if not expected:
            return self.server.server_address[0] in ("127.0.0.1", "::1", "localhost")
        supplied = self.headers.get("Authorization", "")
        return hmac.compare_digest(supplied, "Bearer " + expected)

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def _request_id(self) -> str:
        incoming = self.headers.get("X-Request-ID", "")
        if incoming and len(incoming) <= 128 and _control_free(incoming):
            return incoming
        return "req-" + uuid.uuid4().hex

    def do_GET(self):
        request_id = self._request_id()
        path = urlparse(self.path).path
        try:
            if path == "/livez":
                return self._send(200, self.service.live(), headers={"X-Request-ID": request_id})
            if path == "/health":
                return self._send(200, self.service.health(), headers={"X-Request-ID": request_id})
            if path == "/readyz":
                health = self.service.health()
                if health.get("status") != "OK":
                    return self._send(
                        503,
                        {
                            "status": "NOT_READY",
                            "reason": "runtime_health_degraded",
                            "health": health,
                        },
                        headers={"X-Request-ID": request_id},
                    )
                return self._send(
                    200,
                    {"status": "READY", "version": VERSION},
                    headers={"X-Request-ID": request_id},
                )
            if not self._auth():
                return self._send(
                    401, {"error": "unauthorized"}, headers={"X-Request-ID": request_id}
                )
            if path == "/api/v1/integrations":
                return self._send(
                    200,
                    {"items": self.service.integrations()},
                    headers={"X-Request-ID": request_id},
                )
            if path == "/api/v1/events":
                query = parse_qs(urlparse(self.path).query, keep_blank_values=True)
                tenant = (query.get("tenant") or [None])[0]
                raw_limit = (query.get("limit") or [100])[0]
                try:
                    limit = int(raw_limit)
                except (TypeError, ValueError):
                    return self._send(
                        400, {"error": "invalid_limit"}, headers={"X-Request-ID": request_id}
                    )
                if not 1 <= limit <= 1000:
                    return self._send(
                        400, {"error": "limit_out_of_range"}, headers={"X-Request-ID": request_id}
                    )
                return self._send(
                    200,
                    {"items": self.service.events(tenant, limit)},
                    headers={"X-Request-ID": request_id},
                )
            if path == "/api/v1/evidence/verify":
                return self._send(
                    200, self.service.verify_evidence(), headers={"X-Request-ID": request_id}
                )
            if path.startswith("/api/v1/actions/"):
                action_id = path.rsplit("/", 1)[-1]
                if not action_id or len(action_id) > 128 or not _control_free(action_id):
                    return self._send(
                        400, {"error": "invalid_action_id"}, headers={"X-Request-ID": request_id}
                    )
                action = self.service.action(action_id)
                return (
                    self._send(200, action, headers={"X-Request-ID": request_id})
                    if action
                    else self._send(
                        404, {"error": "not_found"}, headers={"X-Request-ID": request_id}
                    )
                )
            if path in ("/", "/console"):
                html = CONSOLE.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.end_headers()
                self.wfile.write(html)
                return
            return self._send(404, {"error": "not_found"}, headers={"X-Request-ID": request_id})
        except Exception:
            return self._send(
                503,
                {"error": "service_unavailable", "request_id": request_id},
                headers={"X-Request-ID": request_id},
            )

    def do_POST(self):
        request_id = self._request_id()
        try:
            if not self._auth():
                return self._send(
                    401, {"error": "unauthorized"}, headers={"X-Request-ID": request_id}
                )
            if urlparse(self.path).path != "/api/v1/actions":
                return self._send(404, {"error": "not_found"}, headers={"X-Request-ID": request_id})
            content_type = self.headers.get("Content-Type", "")
            if not content_type.lower().startswith("application/json"):
                return self._send(
                    415, {"error": "content_type_required"}, headers={"X-Request-ID": request_id}
                )
            raw_length = self.headers.get("Content-Length", "0")
            try:
                length = int(raw_length)
            except ValueError:
                return self._send(
                    400, {"error": "invalid_content_length"}, headers={"X-Request-ID": request_id}
                )
            if length <= 0 or length > MAX_BODY:
                return self._send(
                    413, {"error": "body_size_invalid"}, headers={"X-Request-ID": request_id}
                )
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                return self._send(
                    400, {"error": "json_object_required"}, headers={"X-Request-ID": request_id}
                )
            if _has_unicode_surrogate(body):
                return self._send(
                    400, {"error": "invalid_unicode"}, headers={"X-Request-ID": request_id}
                )
            out = self.service.submit(body, idempotency_key=self.headers.get("Idempotency-Key"))
            in_progress = bool(out.pop("_idempotency_in_progress", False))
            replayed = bool(out.pop("_idempotency_replayed", False))
            if in_progress:
                return self._send(
                    409,
                    {"error": "idempotency_in_progress", "action": out.get("action_id")},
                    headers={
                        "X-Request-ID": request_id,
                        "Retry-After": "1",
                        "X-Idempotency-Replayed": "true",
                    },
                )
            return self._send(
                200 if replayed else 201,
                out,
                headers={
                    "X-Request-ID": request_id,
                    "X-Idempotency-Replayed": "true" if replayed else "false",
                },
            )
        except IdempotencyConflictError:
            return self._send(
                409, {"error": "idempotency_conflict"}, headers={"X-Request-ID": request_id}
            )
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            return self._send(
                400,
                {"error": "invalid_request", "detail": str(exc)},
                headers={"X-Request-ID": request_id},
            )
        except Exception:
            return self._send(
                500,
                {"error": "internal_error", "request_id": request_id},
                headers={"X-Request-ID": request_id},
            )


class BoundedHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, handler, max_concurrency=64):
        super().__init__(server_address, handler)
        self._capacity = threading.BoundedSemaphore(max(8, min(int(max_concurrency), 512)))

    def process_request(self, request, client_address):
        if not self._capacity.acquire(False):
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nRetry-After: 1\r\nContent-Length: 0\r\n\r\n"
                )
            except Exception:
                pass
            finally:
                request.close()
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._capacity.release()


CONSOLE = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>APC Operations Console</title><style>body{font:16px system-ui;background:#0b1220;color:#e5edf8;margin:0}header{padding:24px 5%;background:#111c30;border-bottom:1px solid #263752}main{max-width:1100px;margin:28px auto;padding:0 20px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:16px}.card{background:#121e32;border:1px solid #2b3b55;border-radius:12px;padding:18px}h1{margin:0 0 8px}h2{font-size:18px}code{color:#8de3ce}.warn{color:#ffd27b}.muted{color:#a9b8cc}button{padding:10px 14px;border-radius:8px;border:0;background:#a5e9d5;color:#10221e;font-weight:700;cursor:pointer}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style></head><body><header><h1>APC <span class="muted">Operations Console</span></h1><div class="muted">Product foundation · local mode · no production effects enabled</div></header><main><div class="grid"><section class="card"><h2>Runtime status</h2><pre id="health">Loading…</pre></section><section class="card"><h2>Evidence chain</h2><pre id="evidence">Loading…</pre><button onclick="loadAll()">Refresh</button></section><section class="card"><h2>Integrations</h2><pre id="integrations">Loading…</pre></section></div><section class="card" style="margin-top:16px"><h2>Recent security events</h2><pre id="events">Loading…</pre></section><p class="warn">This console is an operational foundation, not a certified production console. Demo-mode results are synthetic and never represent real provider effects.</p></main><script>async function get(p){let r=await fetch(p);return r.json()}async function loadAll(){for(let [id,p] of [['health','/health'],['evidence','/api/v1/evidence/verify'],['integrations','/api/v1/integrations'],['events','/api/v1/events']]){try{document.getElementById(id).textContent=JSON.stringify(await get(p),null,2)}catch(e){document.getElementById(id).textContent='Unavailable: '+e}}}loadAll();</script></body></html>"""


def serve(host="127.0.0.1", port=8787):
    Handler.service = APCService()
    if host not in ("127.0.0.1", "::1", "localhost"):
        token = os.getenv("APC_ADMIN_TOKEN", "")
        if not token:
            raise RuntimeError("APC_ADMIN_TOKEN is required when APC binds beyond localhost")
        if len(token) < 32:
            raise RuntimeError(
                "APC_ADMIN_TOKEN must be at least 32 characters when APC binds beyond localhost"
            )
    max_concurrency = int(os.getenv("APC_MAX_CONCURRENCY", "64"))
    server = BoundedHTTPServer((host, port), Handler, max_concurrency=max_concurrency)
    print(f"APC Product Runtime listening at http://{host}:{port} (effect execution disabled)")
    server.serve_forever()

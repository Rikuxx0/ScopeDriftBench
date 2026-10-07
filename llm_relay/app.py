from __future__ import annotations

import http.client
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


MAX_REQUEST_BYTES = 8 * 1024 * 1024
MODEL_CATALOG = Path(__file__).with_name("models.json").read_bytes()
API_KEY_PATHS = {"/v1/responses", "/v1/chat/completions", "/v1/models"}
OAUTH_PATHS = {
    "auth.openai.com": {
        "/api/accounts/deviceauth/usercode",
        "/api/accounts/deviceauth/token",
        "/oauth/token",
    },
    "chatgpt.com": {
        "/backend-api/codex/models",
        "/backend-api/codex/responses",
    },
}
OAUTH_METHODS = {
    ("auth.openai.com", "/api/accounts/deviceauth/usercode"): {"POST"},
    ("auth.openai.com", "/api/accounts/deviceauth/token"): {"POST"},
    ("auth.openai.com", "/oauth/token"): {"POST"},
    ("chatgpt.com", "/backend-api/codex/models"): {"GET"},
    ("chatgpt.com", "/backend-api/codex/responses"): {"POST"},
}
HOP_BY_HOP = {
    "connection", "content-length", "host", "keep-alive",
    "proxy-authenticate", "proxy-authorization", "te", "trailer",
    "transfer-encoding", "upgrade",
}


def normalized_path(path: str) -> str:
    return path.split("?", 1)[0]


def path_allowed(path: str) -> bool:
    """Legacy API route predicate retained for explicit rejection tests."""
    return normalized_path(path) in API_KEY_PATHS


def oauth_path_allowed(host: str, path: str) -> bool:
    return normalized_path(path) in OAUTH_PATHS.get(host.split(":", 1)[0].lower(), set())


def oauth_request_allowed(method: str, host: str, path: str) -> bool:
    route = (host.split(":", 1)[0].lower(), normalized_path(path))
    return method.upper() in OAUTH_METHODS.get(route, set())


def catalog_path_allowed(path: str) -> bool:
    return normalized_path(path) == "/models/api.json"


class BaseRelayHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:
        print(f"llm-relay {self.address_string()} {format % args}", flush=True)

    def send_json(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode()
        # Every relay response deliberately ends the downstream connection.
        # Keep BaseHTTPRequestHandler's request-loop state consistent with the
        # emitted ``Connection: close`` header.
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def request_body(self) -> bytes | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(400, {"error": "invalid content length"})
            return None
        if length < 0 or length > MAX_REQUEST_BYTES:
            self.send_json(413, {"error": "request body too large"})
            return None
        return self.rfile.read(length) if length else b""

    def forward(self, upstream: str, body: bytes, upstream_path: str | None = None) -> None:
        headers = {name: value for name, value in self.headers.items() if name.lower() not in HOP_BY_HOP}
        headers["Host"] = upstream
        connection = http.client.HTTPSConnection(
            upstream, 443, timeout=600, context=ssl.create_default_context()
        )
        response_started = False
        try:
            connection.request(self.command, upstream_path or self.path, body=body, headers=headers)
            response = connection.getresponse()
            # Content-Length and Transfer-Encoding are intentionally stripped,
            # so EOF is the downstream response delimiter. Ensure the handler
            # really closes the TLS connection after this request.
            self.close_connection = True
            response_started = True
            self.send_response(response.status)
            for name, value in response.getheaders():
                if name.lower() not in HOP_BY_HOP:
                    self.send_header(name, value)
            self.send_header("Connection", "close")
            self.end_headers()
            # HTTPResponse.read(size) may wait until ``size`` bytes or EOF. The
            # Codex endpoint is an SSE stream, so read1() is required to forward
            # each available upstream chunk without buffering the whole turn.
            while chunk := response.read1(65536):
                self.wfile.write(chunk)
                self.wfile.flush()
        except Exception as exc:
            self.close_connection = True
            if response_started:
                # Status and possibly part of the body are already on the wire.
                # A second HTTP response on the same TLS stream corrupts framing
                # and previously produced SSL BAD_LENGTH errors. Closing is the
                # only valid recovery; PentestCode can retry the request.
                self.log_error(
                    "relay stream closed after response started: %s", type(exc).__name__
                )
            else:
                try:
                    self.send_json(
                        502, {"error": f"provider relay failure: {type(exc).__name__}"}
                    )
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    self.log_error(
                        "client disconnected before relay error response: %s",
                        type(exc).__name__,
                    )
        finally:
            connection.close()


class HealthHandler(BaseRelayHandler):
    def do_GET(self) -> None:
        if self.path == "/health":
            self.send_json(200, {"status": "ok", "auth_mode": "chatgpt_oauth"})
            return
        if catalog_path_allowed(self.path):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(MODEL_CATALOG)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(MODEL_CATALOG)
            return
        self.send_json(403, {"error": "provider route is not allowlisted"})

    do_POST = do_GET


class OAuthRelayHandler(BaseRelayHandler):
    def do_GET(self) -> None:
        self.proxy()

    def do_POST(self) -> None:
        self.proxy()

    def proxy(self) -> None:
        host = self.headers.get("Host", "").split(":", 1)[0].lower()
        if not oauth_request_allowed(self.command, host, self.path):
            self.send_json(403, {"error": "OAuth provider route is not allowlisted"})
            return
        body = self.request_body()
        if body is None:
            return
        self.forward(host, body)


def serve() -> None:
    health = ThreadingHTTPServer(("0.0.0.0", 8090), HealthHandler)
    threading.Thread(target=health.serve_forever, daemon=True).start()

    oauth = ThreadingHTTPServer(("0.0.0.0", 443), OAuthRelayHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/certs/oauth-relay.crt", "/certs/oauth-relay.key")
    oauth.socket = context.wrap_socket(oauth.socket, server_side=True)
    oauth.serve_forever()


if __name__ == "__main__":
    serve()

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/health":
            self._json(200, {"status": "healthy"})
        elif self.path == "/v1/models":
            self._json(200, {
                "object": "list",
                "data": [{"id": "mock-governance-model", "object": "model"}],
                "synthetic": True,
            })
        else:
            self._json(404, {"error": "not found", "synthetic": True})

    def _json(self, status: int, body: dict[str, object]) -> None:
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        print(f"mock-control-plane {self.client_address[0]} {format % args}", flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8443), Handler).serve_forever()

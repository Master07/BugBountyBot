"""Self-hosted OOB callback listener — binds to localhost only.

Purpose: confirm blind SSRF/XXE/CMDi by catching HTTP callbacks from the target.
Each SSRF payload embeds a unique token; a callback to /<token> proves the
server fetched the URL. Correlated callbacks are stored in the artifact store.

Security: never binds beyond 127.0.0.1 without explicit user approval.
"""
from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable

CallbackHandler = Callable[[str, dict], None]


@dataclass
class OOBServer:
    host: str = "127.0.0.1"
    port: int = 8080
    public_base_url: str = ""  # externally-reachable URL for callback_url()
    _callbacks: list[dict] = field(default_factory=list)
    _server: ThreadingHTTPServer | None = None
    _thread: threading.Thread | None = None
    on_callback: CallbackHandler | None = None
    artifact_store: object | None = None

    def __post_init__(self):
        owner = self  # capture the OOBServer instance for the handler closure

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                self._record()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length) if length else b""
                self._record(body.decode("utf-8", errors="replace"))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def _record(self):
                entry = {
                    "path": self.path,
                    "headers": dict(self.headers),
                    "client": self.client_address[0],
                }
                owner._callbacks.append(entry)
                if owner.on_callback:
                    owner.on_callback(self.path, entry)
                if owner.artifact_store:
                    owner.artifact_store.save_text(
                        f"OOB callback: {self.path}\n{entry}",
                        suffix=".oob",
                    )

            def log_message(self, fmt, *args):
                pass  # silence default stderr logging

        self._handler_cls = _Handler

    # --- lifecycle ---
    def start(self) -> "OOBServer":
        self._server = ThreadingHTTPServer((self.host, self.port), self._handler_cls)
        # When port=0, the OS picks a free port; report the real one.
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        # Wait until the socket is actually accepting connections.
        import socket

        for _ in range(50):
            try:
                with socket.create_connection((self.host, self.port), timeout=0.2):
                    break
            except OSError:
                import time

                time.sleep(0.02)
        return self

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    @property
    def running(self) -> bool:
        return self._server is not None

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def make_token(self) -> str:
        return uuid.uuid4().hex

    def callback_url(self, token: str) -> str:
        if self.public_base_url:
            return f"{self.public_base_url.rstrip('/')}/{token}"
        return f"{self.base_url}/{token}"

    def has_callback(self, token: str) -> bool:
        return any(cb.get("path", "").strip("/") == token for cb in self._callbacks)

    def callbacks_for(self, token: str) -> list[dict]:
        return [cb for cb in self._callbacks if cb.get("path", "").strip("/") == token]

    def clear(self):
        self._callbacks.clear()

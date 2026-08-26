"""Benchmark fixture target — labeled vuln/clean routes with ground truth.

Each route is either a known-vulnerable case (expected_vuln=True) or a
known-clean control (expected_vuln=False). The benchmark runs each module
against its labeled routes and measures precision/recall/FP-rate.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import yaml

# Regression corpus: id -> case (served at /corpus/<id>).
_CORPUS: dict = {}
_corpus_path = Path(__file__).resolve().parent / "corpus.yaml"
if _corpus_path.exists():
    for case in yaml.safe_load(_corpus_path.read_text()) or []:
        _CORPUS[case["id"]] = case

# Ground truth per module: (path-prefix, expected_vuln)
GROUND_TRUTH: dict[str, list[tuple[str, bool]]] = {
    "xss": [
        ("/xss/reflected", True),   # raw reflection -> executable
        ("/xss/encoded", False),    # HTML-encoded, no exec
    ],
    "sqli": [
        ("/sqli/boolean", True),    # 1=1 vs 1=2 differ
        ("/sqli/clean", False),     # identical responses
    ],
    "redirect": [
        ("/redirect/open", True),   # 3xx Location reflects probe
        ("/redirect/benign", False),  # 200, no Location
    ],
    "cors": [
        ("/cors/reflected", True),  # ACAO reflects evil origin
        ("/cors/clean", False),     # no ACAO
    ],
    "idor": [
        ("/idor/resource", True),   # 200 on any id
        ("/idor/clean", False),     # 403 on alt id
    ],
    "secrets": [
        ("/", True),                # .git/config exposed on this host
    ],
}


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        params = dict(parse_qsl(urlsplit(self.path).query))
        path = urlsplit(self.path).path
        q = params.get("q", "")
        url = params.get("url", "")

        # ---- regression corpus: /corpus/<id> serves the case's response ----
        if path.startswith("/corpus/"):
            # strip a trailing numeric segment (idor resource path)
            case_id = path.split("/")[-1]
            if case_id.isdigit():
                case_id = path.split("/")[-2]
            case = _CORPUS.get(case_id)
            if case is None:
                self.send_response(404)
                self.end_headers()
                return
            resp = case.get("response", {})
            body = resp.get("body", "").replace("{PROBE}", q).replace("{RANDOM}", "x")
            self.send_response(resp.get("status", 200))
            for k, v in (resp.get("headers") or {}).items():
                if "{PROBE}" in v:
                    v = v.replace("{PROBE}", "https://evil.com")
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body.encode())
            return

        # ---- XSS ----
        if path.startswith("/xss/reflected"):
            body = f"<html><body>results for {q}</body></html>".encode()
            self._ok(body)
        elif path.startswith("/xss/encoded"):
            import html as _html

            body = f"<html><body>results for {_html.escape(q)}</body></html>".encode()
            self._ok(body)
        # ---- SQLi ----
        elif path.startswith("/sqli/boolean"):
            if "1=1" in q:
                body = b"<html>user: admin (1=1 true)</html>"
            elif "1=2" in q:
                body = b"<html>SQL syntax error near ... MySQL</html>"
            else:
                body = b"<html>ok</html>"
            self._ok(body)
        elif path.startswith("/sqli/clean"):
            self._ok(b"<html>always the same</html>")
        # ---- Redirect ----
        elif path.startswith("/redirect/open"):
            self.send_response(302)
            self.send_header("Location", url)
            self.end_headers()
        elif path.startswith("/redirect/benign"):
            self._ok(b"<html>location: not a redirect</html>")
        # ---- CORS ----
        elif path.startswith("/cors/reflected"):
            origin = self.headers.get("Origin", "")
            self.send_response(200)
            if "evil.com" in origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(b"ok")
        elif path.startswith("/cors/clean"):
            self._ok(b"ok")
        # ---- IDOR ----
        elif path.startswith("/idor/resource"):
            self._ok(f"<html>resource {params.get('id','')}</html>".encode())
        elif path.startswith("/idor/clean"):
            if params.get("id") == "1":
                self._ok(b"<html>resource 1</html>")
            else:
                self.send_response(403)
                self.end_headers()
        elif path == "/.git/config":
            self._ok(b"[core]\n\tbare = false")
        else:
            self._ok(b"ok")

    def _ok(self, body: bytes):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def start_fixture() -> ThreadingHTTPServer:
    """Start the fixture server; returns the running server (port via .server_address)."""
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd

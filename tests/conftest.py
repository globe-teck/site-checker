import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

PAGES = {
    "/": (200, {"Strict-Transport-Security": "max-age=31536000", "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "camera=()", "Content-Security-Policy-Report-Only": "default-src 'self'"},
          b'<html><a href="/ok">ok</a><a href="/missing">x</a><img src="/img.png"><a href="#top">t</a>'
          b'<a href="mailto:someone@example.com">m</a><a href="/ok#frag">dup</a></html>'),
    "/ok": (200, {}, b"ok"),
    "/img.png": (200, {}, b"png"),
    "/slow": (200, {}, b"slow"),
    "/redirect-perm": (301, {"Location": "https://example.com/"}, b""),
    "/redirect-temp": (302, {"Location": "https://example.com/"}, b""),
    "/err": (500, {}, b"boom"),
}


class Handler(BaseHTTPRequestHandler):
    def _go(self, body=True):
        code, hdrs, data = PAGES.get(self.path, (404, {}, b"nf"))
        self.send_response(code)
        for k, v in hdrs.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if body:
            self.wfile.write(data)

    def do_GET(self):
        self._go()

    def do_HEAD(self):
        self._go(False)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="session")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture(autouse=True)
def no_external_network(monkeypatch):
    """Allow loopback only, so tests can never reach the internet."""
    real = socket.create_connection

    def guarded(addr, *a, **k):
        if addr[0] not in ("127.0.0.1", "localhost"):
            raise OSError("network disabled in tests")
        return real(addr, *a, **k)
    monkeypatch.setattr(socket, "create_connection", guarded)

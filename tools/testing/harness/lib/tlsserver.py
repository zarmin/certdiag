"""A loopback HTTPS/HTTP server for network-free remote tests.

Serves a few fixed routes: "/" (a greeting), "/final" (a body the redirect
tests look for), "/redir" (302 to /final), "/loop" (302 to itself) and
"/issuer.der" (an issuer certificate for AIA fetches, when one is given).
"""

import http.server
import socket
import socketserver
import ssl
import threading


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):
        pass

    def _send(self, code, body=b"", headers=None, ctype="text/plain"):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/issuer.der" and self.server.issuer_der is not None:
            return self._send(200, self.server.issuer_der, ctype="application/pkix-cert")
        if path == "/redir":
            return self._send(302, b"", {"Location": "/final"})
        if path == "/loop":
            return self._send(302, b"", {"Location": "/loop"})
        if path == "/final":
            return self._send(200, b"final stop\n")
        return self._send(200, b"hello from local tls\n")

    do_HEAD = do_GET


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class _Server6(_Server):
    address_family = socket.AF_INET6


class LocalServer:
    """Start with certfile/keyfile for HTTPS, without for plain HTTP."""

    def __init__(self, certfile=None, keyfile=None, host="127.0.0.1", issuer_der=None):
        cls = _Server6 if ":" in host else _Server
        self.httpd = cls((host, 0), _Handler)
        self.httpd.issuer_der = issuer_der
        if certfile:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile, keyfile)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.host = host
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def target(self):
        if ":" in self.host:
            return f"[{self.host}]:{self.port}"
        return f"{self.host}:{self.port}"

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()

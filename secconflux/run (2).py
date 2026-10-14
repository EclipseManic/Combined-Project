#!/usr/bin/env python3
"""SecConflux 2.0 Production Static & API Reverse-Proxy Gateway (Zero-Dependency Python)."""
import http.server
import socketserver
import urllib.request
import urllib.error
import os

PORT = int(os.environ.get("SECCONFLUX_PORT", "8080"))
BACKENDS = {
    "/api/malware": os.environ.get("MALWARE_BACKEND", "http://127.0.0.1:5000"),
    "/api/ioc": os.environ.get("IOC_BACKEND", "http://127.0.0.1:8000"),
    "/api/events": os.environ.get("EVENTS_BACKEND", "http://127.0.0.1:5001"),
    "/api/phishing": os.environ.get("PHISHING_BACKEND", "http://127.0.0.1:5002"),
    "/api/ruleforge": os.environ.get("RULEFORGE_BACKEND", "http://127.0.0.1:8765"),
}

class SecConfluxGateway(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        for prefix, target in BACKENDS.items():
            if self.path.startswith(prefix):
                return self.proxy_request(target + self.path)
        return super().do_GET()

    def do_POST(self):
        for prefix, target in BACKENDS.items():
            if self.path.startswith(prefix):
                return self.proxy_request(target + self.path)
        self.send_error(404, "Endpoint not found")

    def proxy_request(self, upstream_url):
        try:
            req = urllib.request.Request(upstream_url, method=self.command)
            with urllib.request.urlopen(req, timeout=15) as resp:
                self.send_response(resp.status)
                for k, v in resp.getheaders():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(resp.read())
        except urllib.error.URLError as exc:
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(f'{{"error": "Bad Gateway", "detail": "{exc}"}}'.encode())

if __name__ == "__main__":
    with socketserver.TCPServer(("127.0.0.1", PORT), SecConfluxGateway) as httpd:
        print(f"SecConflux 2.0 Gateway serving on http://127.0.0.1:{PORT}")
        httpd.serve_forever()

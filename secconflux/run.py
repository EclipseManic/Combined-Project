"""Start the SecConflux UI and open it in a browser.

    python run.py

There is no backend wired up yet. This serves the built interface only, so
every tool page renders from fixtures. When the backends are connected they
are mounted under `/tool/<id>/` on this same origin, which is why the router
is hash-based: the shell's routes live in a namespace that cannot collide
with a proxied backend's mounts.

WHAT IT DELIBERATELY DOES NOT DO

* IT DOES NOT BIND 0.0.0.0. Nothing here has authentication. Loopback only.
* IT DOES NOT ENABLE A DEBUGGER. The Werkzeug debugger is an interactive
  console that executes arbitrary code in this process.
* IT DOES NOT PRINT A DIFFERENT PORT THAN THE ONE IT SERVES. If the default
  is busy it says which port it actually bound.
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading
import time
import webbrowser
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "ui" / "dist"

DEFAULT_PORT = 7000
PORT_ATTEMPTS = 20
HOST = "127.0.0.1"


def _port_is_free(host: str, port: int) -> bool:
    """True when nothing is already LISTENING on host:port.

    A connect probe, not a bind, because a bind on a busy port would fail
    for reasons that have nothing to do with whether we can serve here.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.4)
        return probe.connect_ex((host, port)) != 0


def _find_port(host: str, preferred: int) -> int:
    for offset in range(PORT_ATTEMPTS):
        candidate = preferred + offset
        if _port_is_free(host, candidate):
            return candidate
    raise SystemExit(
        f"Could not find a free port.\n"
        f"  Tried {preferred} to {preferred + PORT_ATTEMPTS - 1} on {host}.\n"
        f"  Something else may have them, or this account may not have\n"
        f"  permission to bind. Try:  python run.py --port 8080"
    )


class Handler(SimpleHTTPRequestHandler):
    """Static files, plus a catch-all that returns index.html.

    The catch-all is what makes deep links work. Without it, refreshing on
    /t/malware would 404, because that file does not exist on disk. The
    browser is meant to own the hash, and the hash is never sent to a
    server, so this handler only ever sees the shell's own document.
    """

    def do_GET(self) -> None:  # noqa: N802
        path = self.translate_path(self.path)
        if not Path(path).is_file():
            self.path = "/index.html"
        super().do_GET()

    def log_message(self, fmt: str, *args: object) -> None:
        """Quiet by default. Pass --verbose to see requests."""


def main() -> int:
    ap = argparse.ArgumentParser(description="Serve the SecConflux UI.")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"port to try first (default {DEFAULT_PORT})")
    ap.add_argument("--host", default=HOST, help=f"bind address (default {HOST})")
    ap.add_argument("--no-browser", action="store_true", help="do not open a browser")
    ap.add_argument("--verbose", action="store_true", help="log every request")
    args = ap.parse_args()

    if not DIST.is_dir():
        print(
            "SecConflux has not been built yet.\n"
            f"  Expected: {DIST}\n"
            "  Build it with:\n\n"
            "      cd ui\n"
            "      npm install\n"
            "      npm run build\n",
            file=sys.stderr,
        )
        return 1

    port = _find_port(args.host, args.port)

    if not args.verbose:
        Handler.log_message = lambda self, fmt, *a: None  # type: ignore[method-assign]

    handler = partial(Handler, directory=str(DIST))
    try:
        httpd = ThreadingHTTPServer((args.host, port), handler)
    except OSError as exc:
        print(
            f"\nCould not start on port {port}: {exc}\n"
            f"  Another program may have taken it between the check and the start.\n"
            f"  Try again, or pass --port to choose one.\n",
            file=sys.stderr,
        )
        return 1

    url = f"http://{args.host}:{port}/"
    print()
    print("  SecConflux — Unified SecOps Utility")
    print(f"  {url}")
    if port != args.port:
        print(f"  (port {args.port} was busy, so this is on {port})")
    print()
    print("  Landing page is the SecConflux overview. Press Ctrl+K anywhere for the")
    print("  command palette, or 1-5 to jump straight to a tool.")
    print()
    print("  UI only for now — the five backends are not connected yet.")
    print("  Ctrl+C to stop.")
    print()

    if not args.no_browser:
        threading.Thread(target=lambda: (time.sleep(0.6), webbrowser.open(url)), daemon=True).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

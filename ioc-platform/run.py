import os
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path

import uvicorn

from app.backend.config import settings

PROJECT_ROOT = Path(__file__).resolve().parent


def _display_url() -> str:
    """A URL the user can open locally, even when the bind host is 0.0.0.0."""
    host = settings.host
    if host in ("0.0.0.0", "::", ""):
        host = "localhost"
    return f"http://{host}:{settings.port}/"


def _connect_host() -> str:
    """The address to dial when probing our own listener.

    A wildcard bind is reachable over loopback, not over 0.0.0.0 itself.
    """
    if settings.host in ("0.0.0.0", "::", ""):
        return "127.0.0.1"
    return settings.host


def _wait_until_serving(timeout: float = 60.0) -> bool:
    """Poll until the server actually accepts connections.

    uvicorn binds inside the reloader's child process, so nothing is
    reachable until that child has imported the app and finished its
    lifespan startup.  A fixed sleep either opens the browser too early
    or wastes time when startup is fast.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((_connect_host(), settings.port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def _open_browser_when_ready(url: str) -> None:
    """Open the browser as soon as the port is live instead of on a timer.

    Daemon so a failed boot, or Ctrl+C during startup, is not held open by
    the watcher thread.
    """

    def _open() -> None:
        if _wait_until_serving():
            webbrowser.open(url)

    threading.Thread(target=_open, daemon=True).start()


def _server_options() -> dict:
    options: dict = {
        "host": settings.host,
        "port": settings.port,
        "reload": settings.reload,
    }
    if settings.reload:
        # Without reload_dirs uvicorn watches the project root, which
        # contains ui/node_modules and .git (~10k files).  That makes the
        # boot scan slow and lets npm or git activity trigger reloads.
        # Only app/ holds server code, so watch that and nothing else.
        options["reload_dirs"] = [str(PROJECT_ROOT / "app")]
        options["reload_includes"] = ["*.py"]
        options["reload_excludes"] = ["*.pyc", "__pycache__/*"]
    return options


def main() -> int:
    os.chdir(PROJECT_ROOT)

    url = _display_url()
    if not settings.disable_auto_open:
        _open_browser_when_ready(url)

    print(f"Starting IOC Lookup Platform at {url}")
    print("Press Ctrl+C to stop")

    try:
        uvicorn.run("app.backend.main:app", **_server_options())
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""A deliberately VULNERABLE MCP server. Your punching bag.

It exposes one tool, read_file, that is SUPPOSED to only read inside the
allowed directory. The bug: it joins the user path straight onto the base
with no containment check, so `../../../secret_canary` escapes.

This exists so the harness always has something safe to catch. Never copy
this pattern into real code.

Run standalone:
    HARNESS_ALLOWED_DIR=./data python3 -m testserver.server

Note: no `from __future__ import annotations` here on purpose. FastMCP
introspects the tool signature at decoration time and needs the real `str`
type, not a stringized annotation.
"""
import logging
import os
import socket
import subprocess
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

# keep the demo output clean; the server's per-request info logs go to stderr
logging.getLogger("mcp").setLevel(logging.WARNING)

mcp = FastMCP("vulnerable-testserver")

ALLOWED_DIR = os.environ.get("HARNESS_ALLOWED_DIR", "./data")


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file from the data directory."""
    # VULNERABLE ON PURPOSE: no is_relative_to() containment check.
    full = os.path.join(ALLOWED_DIR, path)
    # also honor an absolute path, compounding the bug
    if os.path.isabs(path):
        full = path
    try:
        with open(full, "r", errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        return f"[not found: {path}]"
    except Exception as e:  # noqa: BLE001
        return f"[error: {e}]"


@mcp.tool()
def fetch_url(url: str) -> str:
    """Fetch a URL over HTTP and return the start of the response."""
    # VULNERABLE ON PURPOSE: no host allowlist, no SSRF guard. It connects to
    # whatever host:port the caller names, including internal/metadata targets.
    # That blind outbound connection is the SSRF bug the EgressOracle catches.
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        with socket.create_connection((host, port), timeout=2) as sock:
            sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
            return sock.recv(2048).decode("utf-8", errors="replace")
    except Exception as e:  # noqa: BLE001
        return f"[fetch error: {e}]"


@mcp.tool()
def run_command(cmd: str) -> str:
    """Run a shell command and return its combined output."""
    # VULNERABLE ON PURPOSE: shell=True on caller-controlled input is textbook
    # command injection. The spawned child is what the ProcessOracle catches.
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=5
        )
        return proc.stdout + proc.stderr
    except Exception as e:  # noqa: BLE001
        return f"[command error: {e}]"


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()

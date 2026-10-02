"""The box. Isolates one target and plants canaries around it.

TWO MODES:
- docker (the real thing): build an image for the target, plant canary files
  OUTSIDE the allowed dir inside the container, run the server with --network
  none under `strace -f` so the sandbox can observe what the server actually
  did -- every child process it exec'd and every outbound connect() it tried.
- local (fallback for first run / machines without Docker): plant canaries in a
  temp dir on the host and run the server as a plain subprocess. NO isolation,
  and NO egress/process collection (there is no container to observe). Use ONLY
  with the reference server you wrote yourself.

Collection model: the docker launch wraps the server in strace, writing a trace
to a file on the container's tmpfs. handle.collect() reads that file back while
the container is still alive and parses it into egress + process lists for the
oracles. local mode's collect() returns empty lists -- honestly empty, not
faked. See _parse_strace below for exactly what is extracted.
"""
from __future__ import annotations

import os
import re
import secrets
import tempfile
from dataclasses import dataclass, field
from typing import Any, Callable

from .models import Target


@dataclass
class SandboxHandle:
    """What the coordinator needs after a sandbox is set up."""
    launch: list[str]                       # command to start the server
    env: dict[str, str]                     # env passed to that subprocess
    canary_tokens: dict[str, str]           # token -> planted path
    cleanup: Callable[[], None]
    mode: str
    # Returns {"egress": list[dict], "processes": list[str]} collected from the
    # running sandbox. Must be called while the sandbox is still alive. The
    # default is for sandboxes that observe nothing (e.g. local mode).
    collect: Callable[[], dict] = field(
        default_factory=lambda: (lambda: {"egress": [], "processes": []})
    )
    extra: dict = field(default_factory=dict)


def setup_local(target: Target) -> SandboxHandle:
    """Local, unisolated sandbox. Reference server only."""
    workdir = tempfile.mkdtemp(prefix="mcp_harness_")

    allowed = os.path.join(workdir, "data")
    os.makedirs(allowed, exist_ok=True)
    with open(os.path.join(allowed, "readme.txt"), "w") as f:
        f.write("public file the server is allowed to read\n")

    # plant a canary OUTSIDE the allowed dir, named so blind traversal payloads
    # (../secret_canary, ../../secret_canary, ...) can reach it
    token = "CANARY_" + secrets.token_hex(6)
    canary_path = os.path.join(workdir, "secret_canary")
    with open(canary_path, "w") as f:
        f.write(f"TOP SECRET {token} do not leak\n")

    # the subprocess gets a minimal explicit env; this is how the server learns
    # its allowed dir. PATH is included so python3 resolves.
    env = {
        "HARNESS_ALLOWED_DIR": allowed,
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
    }

    def cleanup() -> None:
        import shutil
        shutil.rmtree(workdir, ignore_errors=True)

    return SandboxHandle(
        launch=["python3", "-m", "testserver.server"],
        env=env,
        canary_tokens={token: canary_path},
        cleanup=cleanup,
        mode="local",
    )


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Tag encodes the image contents; bump it when docker/Dockerfile changes so a
# stale image is not silently reused. ":strace" carries the strace observer.
DOCKER_IMAGE = "mcp-harness/testserver:strace"
# Where strace writes its trace inside the container. /tmp is a writable tmpfs
# (the root fs is --read-only). The harness reads this file back via
# `docker exec cat` at collect() time, while the container is still alive.
STRACE_LOG = "/tmp/mcp_harness_strace.log"
# Where the allowed dir and the canary live INSIDE the container. The server's
# allowed dir is /srv/data; the canary sits one level up, just outside it, so a
# `../secret_canary` escape reaches it exactly as it does in local mode.
CONTAINER_ALLOWED_DIR = "/srv/data"
CONTAINER_CANARY_PATH = "/srv/secret_canary"


def _run_docker(args: list[str], **kw) -> "subprocess.CompletedProcess":
    import subprocess
    return subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        **kw,
    )


def _ensure_image() -> None:
    """Build the runtime image if it is not already present."""
    import subprocess

    inspect = _run_docker(["image", "inspect", DOCKER_IMAGE])
    if inspect.returncode == 0:
        return

    build = _run_docker(
        ["build", "-t", DOCKER_IMAGE, "-f",
         os.path.join(REPO_ROOT, "docker", "Dockerfile"),
         os.path.join(REPO_ROOT, "docker")],
        timeout=600,
    )
    if build.returncode != 0:
        raise RuntimeError(
            f"docker build failed:\n{build.stdout}\n{build.stderr}"
        )


def setup_docker(target: Target) -> SandboxHandle:
    """Real isolated sandbox: the server runs inside a locked-down container.

    The container has no network (--network none), no capabilities, a
    read-only root filesystem, and read-only mounts for both the server code
    and its data. The canary — a file with a unique random token — is planted
    just outside the server's allowed dir, mounted in at run time so the token
    never ends up baked into the reusable image.

    The returned launch command is a `docker run ... python3 -m
    testserver.server`, which execs the server inside the container over stdio.
    The existing MCPClient stdio transport drives it unchanged.
    """
    _ensure_image()

    # Build a per-run mount context on the host. It becomes /srv in the
    # container: /srv/data is the allowed dir, /srv/secret_canary is the leak
    # target one level up.
    workdir = tempfile.mkdtemp(prefix="mcp_harness_docker_")
    srv = os.path.join(workdir, "srv")
    allowed = os.path.join(srv, "data")
    os.makedirs(allowed, exist_ok=True)
    with open(os.path.join(allowed, "readme.txt"), "w") as f:
        f.write("public file the server is allowed to read\n")

    # Same token scheme as setup_local: "CANARY_" + hex, inside a file whose
    # contents the CanaryOracle matches against the server's output.
    token = "CANARY_" + secrets.token_hex(6)
    host_canary = os.path.join(srv, "secret_canary")
    with open(host_canary, "w") as f:
        f.write(f"TOP SECRET {token} do not leak\n")

    container_name = "mcp_harness_" + secrets.token_hex(6)

    launch = [
        "docker", "run",
        "--rm",                                  # auto-remove on exit
        "-i",                                    # keep stdin open for stdio
        "--name", container_name,
        "--network", "none",                     # no route out: egress attempts
                                                 # fail ENETUNREACH; strace still
                                                 # records the attempt before the
                                                 # kernel drops it.
        "--cap-drop", "ALL",                     # strip all capabilities
        "--security-opt", "no-new-privileges",   # block setuid escalation
        "--read-only",                           # read-only root filesystem
        "--tmpfs", "/tmp",                       # writable scratch (strace log)
        "-v", f"{REPO_ROOT}:/app:ro",            # server code, read-only
        "-v", f"{srv}:/srv:ro",                  # data + canary, read-only
        "-e", f"HARNESS_ALLOWED_DIR={CONTAINER_ALLOWED_DIR}",
        "-e", "PYTHONPATH=/app",
        "-w", "/app",
        DOCKER_IMAGE,
        # Observe the server in-container. -f follows forks so children count;
        # we trace exactly the two syscalls the oracles care about. strace's own
        # output goes to -o (the log file), leaving stdin/stdout -- the MCP stdio
        # channel, inherited by the child -- untouched. -s keeps argv readable.
        "strace", "-f", "-qq", "-s", "200",
        "-e", "trace=execve,connect",
        "-o", STRACE_LOG,
        "python3", "-m", "testserver.server",
    ]

    # Env for the `docker` CLI process itself (not the server): it needs PATH
    # to resolve the docker binary and HOME for ~/.docker config.
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/root"),
    }

    def collect() -> dict:
        """Read the strace log out of the live container and parse it.

        Called by the coordinator while the container is still running (the
        scenario has finished but the stdio session is not yet closed), because
        --rm destroys the tmpfs the moment the container exits.
        """
        r = _run_docker(["exec", container_name, "cat", STRACE_LOG])
        if r.returncode != 0:
            # Container gone, strace not started, or log not yet created: report
            # nothing rather than guessing. Empty is honest, not a clean verdict.
            return {"egress": [], "processes": []}
        return _parse_strace(r.stdout)

    def cleanup() -> None:
        import shutil
        # --rm usually handles removal; force it in case the run errored early.
        _run_docker(["rm", "-f", container_name])
        shutil.rmtree(workdir, ignore_errors=True)

    return SandboxHandle(
        launch=launch,
        env=env,
        canary_tokens={token: CONTAINER_CANARY_PATH},
        cleanup=cleanup,
        mode="docker",
        collect=collect,
        extra={"container_name": container_name, "image": DOCKER_IMAGE},
    )


# --- strace log parsing -----------------------------------------------------
#
# strace -f lines we care about look like:
#   execve("/bin/sh", ["/bin/sh", "-c", "id"], 0x7ff.. /* 9 vars */) = 0
#   [pid 10] execve("/bin/echo", ["/bin/echo", "hi"], 0x.. /* .. */) = 0
#   connect(3, {sa_family=AF_INET, sin_port=htons(8080),
#               sin_addr=inet_addr("1.2.3.4")}, 16) = -1 ENETUNREACH (...)
#   connect(4, {sa_family=AF_INET6, sin6_port=htons(443), ...,
#               inet_pton(AF_INET6, "2001:db8::1", &sin6_addr), ...}, 28) = ...
#
# A connect() is recorded whether it SUCCEEDS or FAILS: the attempt (the
# destination the server asked for) is the violation, and under --network none
# it always fails -- which is exactly why nothing reaches the real internet.

_EXECVE_RE = re.compile(r'execve\("[^"]*",\s*(\[[^\]]*\])')
_ARG_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
_CONNECT_V4_RE = re.compile(
    r'sa_family=AF_INET,\s*sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\("([^"]+)"\)'
)
_CONNECT_V6_RE = re.compile(
    r'sa_family=AF_INET6,\s*sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6,\s*"([^"]+)"'
)

_LOOPBACK = {"127.0.0.1", "::1", "0.0.0.0", "::"}


def _parse_strace(text: str) -> dict:
    processes: list[str] = []
    seen_proc: set[str] = set()
    egress: list[dict[str, Any]] = []
    seen_egress: set[tuple] = set()

    for line in text.splitlines():
        m = _EXECVE_RE.search(line)
        if m:
            args = _ARG_RE.findall(m.group(1))
            # Skip the server's own launch: strace's first execve is the target
            # server itself, not a process it spawned.
            if any("testserver.server" in a for a in args):
                continue
            cmdline = " ".join(args)
            if cmdline and cmdline not in seen_proc:
                seen_proc.add(cmdline)
                processes.append(cmdline)
            continue

        host = port = None
        m4 = _CONNECT_V4_RE.search(line)
        if m4:
            port, host = int(m4.group(1)), m4.group(2)
        else:
            m6 = _CONNECT_V6_RE.search(line)
            if m6:
                port, host = int(m6.group(1)), m6.group(2)
        if host is None or host in _LOOPBACK:
            continue
        key = (host, port)
        if key not in seen_egress:
            seen_egress.add(key)
            egress.append({"host": host, "port": port})

    return {"egress": egress, "processes": processes}


def setup(target: Target, mode: str = "local") -> SandboxHandle:
    if mode == "local":
        return setup_local(target)
    if mode == "docker":
        return setup_docker(target)
    raise ValueError(f"unknown sandbox mode: {mode}")

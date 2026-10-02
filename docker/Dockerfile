# Runtime image for the reference MCP server under test.
#
# It carries ONLY the interpreter and the MCP SDK. The server code itself is
# bind-mounted read-only at /app at `docker run` time (see harness/sandbox.py),
# so editing testserver/ needs no rebuild, and the running container cannot
# modify the code it is executing.
#
# The canary and the allowed data dir are likewise mounted read-only at run
# time, because their token is random per run and must never be baked into a
# reusable image.
FROM python:3.12-slim

# strace is the in-container observer: the harness launches the server under
# `strace -f` to record child-process execve() and outbound connect() syscalls
# (see harness/sandbox.py). ptrace on same-uid children works with no added
# capability, so the --cap-drop ALL / --no-new-privileges lockdown stays intact.
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends strace \
    && rm -rf /var/lib/apt/lists/*

# Pin to the host's mcp version so the stdio protocol matches the client.
RUN pip install --no-cache-dir "mcp==1.30.0"

# Run as an unprivileged user; combined with --cap-drop ALL and
# --no-new-privileges this leaves the server with no way to escalate.
RUN useradd --create-home --uid 10001 harness
USER harness

WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# No default CMD: the harness supplies `python3 -m testserver.server` so the
# launch command stays explicit and visible in the returned SandboxHandle.

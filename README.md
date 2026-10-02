# MCP Dynamic Exploitation Harness

A test harness that proves security flaws in [Model Context Protocol](https://modelcontextprotocol.io) servers by **running real attacks against them in an isolated sandbox and observing whether a boundary actually breaks**, rather than pattern matching on source code.

Static scanners say *"this looks risky."* This says *"I ran it, and here is the file it leaked."*

## How it works

```
                 coordinator
                     |
         +-----------+-----------+
         |           |           |
      worker      worker      worker        (run N targets in parallel)
         |
   +-----v-----------------------------+
   |   Docker sandbox (--network none) |    one container per target, no route out
   |   +---------------------------+   |
   |   | strace -f (execve,connect)|   |    syscall capture wraps the server
   |   |  +---------------------+  |   |
   |   |  |  target MCP server  |  |   |    the thing under test
   |   |  +---------------------+  |   |
   |   +---------------------------+   |
   |   canary files (secrets)          |    planted OUTSIDE the allowed dir
   +-----------------------------------+
         |
     MCP client  ---- sends attack payloads to the server's tools
         |
       oracle   ---- canary in output? connect() attempted? child exec'd? -> PROVEN
         |
      storage   ---- SQLite / Postgres: runs, findings, captured proof
```

### The key idea: the sandbox is the oracle

A scenario does not decide whether it succeeded. The **sandbox** does. It watches three tripwires:

1. **Filesystem canary** - secret files planted outside the server's allowed path. If a canary's contents ever appear in the server's output, a file leak is **proven**.
2. **Egress monitor** - the server runs under `strace -f` with `--network none`, so there is no route out at all. Any outbound `connect()` the server attempts is captured as a syscall (destination host/port included) *before* the kernel drops it with `ENETUNREACH` - the attempt is logged, nothing reaches the real network. An attempted callout is **proven** SSRF.
3. **Process monitor** - the same `strace -f` records every `execve()`, so any child process the server spawns is **proven** command execution.

Because the oracle judges violations generically, the harness can catch attacks nobody wrote a specific check for. That is what makes it a discovery tool, not just a scanner.

## Roles (plain English)

| Component | Job |
|---|---|
| **target MCP server** | the program being tested |
| **Docker sandbox** | seals the target off from your real machine |
| **MCP client** | the attacker; pretends to be the AI and calls the server's tools with bad input |
| **oracle** | the cameras; watches for proof a boundary broke |
| **coordinator** | the manager; hands jobs to workers and runs several at once |
| **storage** | the notebook; records every run and finding with proof |

There is **no real LLM**. The attacker code sends chosen payloads directly, so results are deterministic, free, and repeatable.

## Tech stack

- **Python 3.11+** with `asyncio` - everything
- **MCP Python SDK** - speak the protocol
- **Docker** - the sandbox
- **FastAPI** - the HTTP service layer over the coordinator
- **SQLite (default) / Postgres** - storage behind one interface, pick via env
- **pytest + GitHub Actions** - tests and CI

Nothing cloud, nothing remote. Runs on your laptop.

## Quick start

```bash
pip install -e .

# run the harness against the deliberately vulnerable reference server
harness run --target testserver

# see findings from the last run
harness report
```

Expected first result: the path traversal scenario trips the filesystem canary, and you get a PROVEN finding with the leaked file contents attached.

## API

The same coordinator and storage are available as an HTTP service, so the
harness is drivable as a backend, not just a CLI.

```bash
pip install -e .                 # fastapi is a core dependency
uvicorn harness.api:app --reload # serves on http://127.0.0.1:8000
```

| Method | Path              | Does                                                         |
|--------|-------------------|-------------------------------------------------------------|
| POST   | `/scans`          | start a scan for a target (runs in the background), returns a run id |
| GET    | `/scans/{id}`     | status of that run (`running` / `completed` / `error`)      |
| GET    | `/findings`       | recent findings; optional `?target=` and `?verdict=` filters |
| GET    | `/findings/{id}`  | one finding with full evidence                              |

```bash
# kick off a scan (docker sandbox by default) and note the returned id
curl -s -X POST localhost:8000/scans \
  -H 'content-type: application/json' \
  -d '{"target":"testserver","mode":"docker"}'

curl -s localhost:8000/scans/<run-id>              # poll status
curl -s 'localhost:8000/findings?verdict=proven'   # proven findings only
curl -s localhost:8000/findings/1                   # one finding + evidence
```

Interactive docs are at `/docs`.

## Storage: SQLite or Postgres

One `Storage` interface, two backends (`save` / `recent` / `get`), selected by
environment so no credentials live in code:

- **SQLite (default)** - a single file, zero setup. Used by the CLI, the tests,
  and the API out of the box.
- **Postgres** - the real backend for the service.

Stand Postgres up with the bundled compose file (one command), then point the
app at it:

```bash
docker compose up -d        # starts Postgres; creds come from env, not code

export HARNESS_DB_BACKEND=postgres
export DATABASE_URL=postgresql://harness:harness@localhost:5432/harness
pip install -e ".[postgres]"   # installs the psycopg driver
uvicorn harness.api:app --reload
```

The compose defaults (`harness`/`harness`) are throwaway local-dev values; set
`POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` (and `POSTGRES_PORT` if
5432 is taken) in the environment or a `.env` file for anything else.

## Hard rules (do not skip)

1. **Local sandbox only.** Never point this at a server you do not own and run yourself.
2. **Fail closed.** If a server hangs or errors, that is a finding or an error, never a silent pass.
3. **Responsible disclosure.** If you ever test a real open source server, follow its disclosure policy before reporting anything.

## Status

MVP in progress. Current: coordinator, Docker sandbox worker (strace-based egress
+ process capture, `--network none`, dropped caps, read-only, non-root), MCP
client, three oracles (filesystem canary, network egress, child process),
path-traversal / SSRF / command-injection scenarios, a seedable payload mutator
(fuzzing), a vulnerable reference server, a FastAPI service layer, SQLite/Postgres
storage, and CI.

Roadmap: more scenario classes, more targets in the registry, and persisting run
state in the store so scan status survives a service restart.

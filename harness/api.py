"""HTTP service layer over the same coordinator the CLI drives.

Endpoints:
    POST /scans          start a scan for a target (runs in the background),
                         returns a run id and status
    GET  /scans/{id}     status of that run
    GET  /findings       recent findings, optional ?target= and ?verdict=
    GET  /findings/{id}  one finding with full evidence

The scan itself runs through the exact same Coordinator / sandbox / oracle path
as `harness run`; this module only adds HTTP and run tracking. Storage is
injected via create_app(), so the API talks to whatever backend open_storage()
selected (SQLite by default, Postgres when the env says so).

Run tracking is in-process (a dict keyed by run id). That is fine for a single
service process; a multi-process deployment would promote it to the store.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from fastapi import BackgroundTasks, FastAPI, HTTPException
from pydantic import BaseModel

from . import registry
from .coordinator import Coordinator, Job
from .storage import Storage, open_storage


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScanRequest(BaseModel):
    target: str
    mode: Literal["local", "docker"] = "docker"
    concurrency: int = 4
    fuzz_iterations: int = 25
    seed: int = 0


async def execute_scan(
    storage: Storage, runs: dict, run_id: str, req: ScanRequest
) -> None:
    """Background worker: run the scan and update the run record.

    Module-level (not a closure) so tests can monkeypatch it to a fast fake
    without standing up a sandbox. Mirrors the CLI's job assembly exactly.
    """
    rec = runs[run_id]
    try:
        target = registry.TARGETS[req.target]
        scenarios = registry.all_scenarios()
        if req.fuzz_iterations > 0:
            from .scenarios.fuzz import FuzzScenario
            scenarios.append(FuzzScenario(req.fuzz_iterations, req.seed))
        jobs = [Job(target=target, scenario=s) for s in scenarios]

        coord = Coordinator(storage, concurrency=req.concurrency, mode=req.mode)
        findings = await coord.run(jobs)

        rec["status"] = "completed"
        rec["finding_count"] = len(findings)
        rec["proven_count"] = sum(1 for f in findings if f.verdict.value == "proven")
    except Exception as e:  # noqa: BLE001 - surface the failure on the run record
        rec["status"] = "error"
        rec["error"] = f"{type(e).__name__}: {e}"
    finally:
        rec["finished_at"] = _now()


def create_app(storage: Storage | None = None) -> FastAPI:
    """Build the API bound to a given storage backend (default: open_storage())."""
    store = storage if storage is not None else open_storage()
    runs: dict[str, dict] = {}

    app = FastAPI(title="MCP Harness API")
    app.state.storage = store
    app.state.runs = runs

    @app.post("/scans", status_code=202)
    async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks) -> dict:
        if req.target not in registry.TARGETS:
            raise HTTPException(
                status_code=404,
                detail=f"unknown target: {req.target}; "
                f"known: {', '.join(registry.TARGETS)}",
            )
        run_id = uuid4().hex
        runs[run_id] = {
            "id": run_id,
            "status": "running",
            "target": req.target,
            "mode": req.mode,
            "started_at": _now(),
            "finished_at": None,
            "finding_count": 0,
            "proven_count": 0,
            "error": None,
        }
        # resolved from the module global at call time, so tests can monkeypatch
        background_tasks.add_task(execute_scan, store, runs, run_id, req)
        return runs[run_id]

    @app.get("/scans/{run_id}")
    async def get_scan(run_id: str) -> dict:
        rec = runs.get(run_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="run not found")
        return rec

    @app.get("/findings")
    def list_findings(
        target: str | None = None, verdict: str | None = None, limit: int = 50
    ) -> list[dict]:
        return store.recent(limit=limit, target=target, verdict=verdict)

    @app.get("/findings/{finding_id}")
    def get_finding(finding_id: int) -> dict:
        found = store.get(finding_id)
        if found is None:
            raise HTTPException(status_code=404, detail="finding not found")
        return found

    return app


# Default app for `uvicorn harness.api:app`. Backend comes from the environment.
app = create_app()

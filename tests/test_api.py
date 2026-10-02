"""API endpoint tests: FastAPI TestClient against the SQLite backend.

No live Postgres and no real sandbox are needed. The read endpoints run against
a seeded SQLite store; the scan endpoint's background worker is monkeypatched to
a fast fake, so we test the HTTP + run-tracking layer without standing up a
container (the real scan path is covered by the coordinator/sandbox tests).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import harness.api as api
from harness.api import create_app
from harness.models import Finding, Verdict
from harness.storage import SQLiteStorage


@pytest.fixture
def store(tmp_path):
    s = SQLiteStorage(str(tmp_path / "api.db"))
    yield s
    s.close()


@pytest.fixture
def client(store):
    return TestClient(create_app(store))


def _seed(store, *, target="testserver", scenario="path_traversal",
          verdict=Verdict.PROVEN, detail="leak", evidence=None):
    evidence = evidence or {"token": "CANARY_x", "oracle": "filesystem_canary"}
    return store.save(Finding(target=target, scenario=scenario, verdict=verdict,
                              detail=detail, evidence=evidence))


def test_list_findings_and_filters(client, store):
    _seed(store, target="testserver", verdict=Verdict.PROVEN)
    _seed(store, target="other", verdict=Verdict.NOT_PROVEN)

    assert len(client.get("/findings").json()) == 2

    by_target = client.get("/findings", params={"target": "testserver"}).json()
    assert [f["target"] for f in by_target] == ["testserver"]

    by_verdict = client.get("/findings", params={"verdict": "not_proven"}).json()
    assert [f["verdict"] for f in by_verdict] == ["not_proven"]

    assert len(client.get("/findings", params={"limit": 1}).json()) == 1


def test_get_one_finding_full_evidence_and_404(client, store):
    fid = _seed(store, evidence={"token": "CANARY_abc", "leaked_output": "secret!"})

    r = client.get(f"/findings/{fid}")
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == fid
    assert body["evidence"]["token"] == "CANARY_abc"
    assert body["evidence"]["leaked_output"] == "secret!"

    assert client.get("/findings/999999").status_code == 404


def test_start_scan_returns_run_id_and_status(client, store, monkeypatch):
    async def fake_execute(storage, runs, run_id, req):
        storage.save(Finding(target=req.target, scenario="path_traversal",
                             verdict=Verdict.PROVEN, detail="fake-scan",
                             evidence={"oracle": "filesystem_canary"}))
        runs[run_id]["status"] = "completed"
        runs[run_id]["finding_count"] = 1
        runs[run_id]["proven_count"] = 1

    monkeypatch.setattr(api, "execute_scan", fake_execute)

    r = client.post("/scans", json={"target": "testserver", "mode": "local"})
    assert r.status_code == 202
    body = r.json()
    run_id = body["id"]
    assert body["target"] == "testserver"
    assert body["status"] == "running"  # status at creation, before the worker

    # TestClient waits for background tasks, so the fake worker has now run.
    status = client.get(f"/scans/{run_id}")
    assert status.status_code == 200
    assert status.json()["status"] == "completed"
    assert status.json()["proven_count"] == 1

    # the finding the worker saved is retrievable through the store/API
    assert any(f["detail"] == "fake-scan" for f in client.get("/findings").json())


def test_start_scan_unknown_target_404(client):
    assert client.post("/scans", json={"target": "does-not-exist"}).status_code == 404


def test_get_unknown_scan_404(client):
    assert client.get("/scans/deadbeef").status_code == 404

"""The test that guards the whole project.

CI runs this on every push. If the harness ever stops catching the planted
path traversal in the reference server, this goes red. That is the signal
that a change broke detection.
"""
from __future__ import annotations

import asyncio
import shutil
import subprocess

import pytest

from harness import registry
from harness.coordinator import Coordinator, Job
from harness.models import Verdict
from harness.oracle.base import Observation
from harness.oracle.canary import CanaryOracle
from harness.oracle.egress import EgressOracle
from harness.oracle.process import ProcessOracle
from harness.fuzzer import Mutator
from harness.scenarios.command_injection import CommandInjectionScenario
from harness.scenarios.fuzz import FuzzScenario
from harness.scenarios.path_traversal import PAYLOADS, PathTraversalScenario
from harness.scenarios.ssrf import SSRFScenario
from harness.storage import SQLiteStorage


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(
            ["docker", "info"], capture_output=True, timeout=15
        ).returncode == 0
    except Exception:
        return False


DOCKER = _docker_available()
requires_docker = pytest.mark.skipif(not DOCKER, reason="docker not available")


def test_canary_oracle_catches_leak():
    """Unit test: the oracle proves a leak when a token appears in output."""
    oracle = CanaryOracle({"CANARY_abc123": "/tmp/secret"})
    obs = Observation(
        outputs=["here is the file:\nTOP SECRET CANARY_abc123 do not leak"],
        egress=[],
        processes=[],
    )
    result = oracle.judge(obs)
    assert result.proven is True
    assert "leaked_output" in result.evidence


def test_canary_oracle_clean_when_no_leak():
    oracle = CanaryOracle({"CANARY_abc123": "/tmp/secret"})
    obs = Observation(outputs=["nothing interesting here"], egress=[], processes=[])
    assert oracle.judge(obs).proven is False


def test_egress_oracle_catches_outbound_request():
    """Unit test: any captured egress proves an unexpected callout."""
    oracle = EgressOracle()
    obs = Observation(
        outputs=[],
        egress=[{"host": "evil.example", "port": 443, "method": "POST"}],
        processes=[],
    )
    result = oracle.judge(obs)
    assert result.proven is True
    assert result.evidence["request_count"] == 1
    assert result.evidence["requests"][0]["host"] == "evil.example"


def test_egress_oracle_clean_when_no_egress():
    oracle = EgressOracle()
    obs = Observation(outputs=["read a file"], egress=[], processes=[])
    assert oracle.judge(obs).proven is False


def test_process_oracle_catches_spawned_child():
    """Unit test: any spawned child process proves command execution."""
    oracle = ProcessOracle()
    obs = Observation(
        outputs=[],
        egress=[],
        processes=["/bin/sh -c id"],
    )
    result = oracle.judge(obs)
    assert result.proven is True
    assert result.evidence["process_count"] == 1
    assert "/bin/sh -c id" in result.evidence["processes"]


def test_process_oracle_clean_when_no_children():
    oracle = ProcessOracle()
    obs = Observation(outputs=["read a file"], egress=[], processes=[])
    assert oracle.judge(obs).proven is False


def test_end_to_end_catches_planted_traversal(tmp_path):
    """Integration: run the real reference server and prove the traversal."""
    storage = SQLiteStorage(str(tmp_path / "test.db"))
    target = registry.TARGETS["testserver"]
    # Only the traversal scenario here: local mode has no sandbox, so we must
    # not fire the SSRF / command-injection scenarios unsandboxed on the host.
    # Those are exercised against the docker sandbox in the tests below.
    jobs = [Job(target=target, scenario=PathTraversalScenario())]

    coord = Coordinator(storage, concurrency=1, mode="local")
    findings = asyncio.run(coord.run(jobs))
    storage.close()

    proven = [f for f in findings if f.verdict == Verdict.PROVEN]
    assert proven, f"expected a proven traversal, got: {[f.verdict for f in findings]}"
    assert proven[0].evidence.get("token", "").startswith("CANARY_")


@requires_docker
def test_ssrf_scenario_proven_by_egress_oracle(tmp_path):
    """Docker e2e: fetch_url's outbound connection is caught by the egress oracle."""
    storage = SQLiteStorage(str(tmp_path / "ssrf.db"))
    target = registry.TARGETS["testserver"]
    job = Job(target=target, scenario=SSRFScenario())

    coord = Coordinator(storage, concurrency=1, mode="docker")
    findings = asyncio.run(coord.run([job]))
    storage.close()

    assert len(findings) == 1
    f = findings[0]
    assert f.verdict == Verdict.PROVEN, f"not proven: {f.detail}"
    assert f.evidence.get("oracle") == "network_egress"
    hosts = [req.get("host") for req in f.evidence.get("requests", [])]
    assert "192.0.2.1" in hosts, f"destination not captured: {hosts}"


def test_mutator_produces_distinct_valid_variations():
    """Unit: the mutator yields distinct, non-seed, reproducible variations."""
    seeds = list(PAYLOADS)
    muts = Mutator(seed=1234).generate(seeds, 20)

    assert len(muts) == 20
    assert len(set(muts)) == 20                      # all distinct
    assert all(isinstance(m, str) and m for m in muts)
    assert all(m not in set(seeds) for m in muts)    # none is a raw seed
    # deterministic: same seed -> same payloads
    assert Mutator(seed=1234).generate(seeds, 20) == muts
    # a different seed produces a different corpus
    assert Mutator(seed=99).generate(seeds, 20) != muts
    # real mutation happened: at least one shows an encoding / null / case tell
    assert any(("%" in m) or ("\x00" in m) or (m != m.lower()) for m in muts)


@requires_docker
def test_fuzzed_traversal_still_trips_canary(tmp_path):
    """Docker e2e: a mutated path-traversal run still proves the canary leak."""
    storage = SQLiteStorage(str(tmp_path / "fuzz.db"))
    target = registry.TARGETS["testserver"]
    job = Job(target=target, scenario=FuzzScenario(iterations=25, seed=0))

    coord = Coordinator(storage, concurrency=1, mode="docker")
    findings = asyncio.run(coord.run([job]))
    storage.close()

    assert len(findings) == 1
    f = findings[0]
    assert f.verdict == Verdict.PROVEN, f"not proven: {f.detail}"
    assert f.evidence.get("oracle") == "filesystem_canary"
    assert f.evidence.get("token", "").startswith("CANARY_")


@requires_docker
def test_command_injection_proven_by_process_oracle(tmp_path):
    """Docker e2e: run_command's child process is caught by the process oracle."""
    storage = SQLiteStorage(str(tmp_path / "cmd.db"))
    target = registry.TARGETS["testserver"]
    job = Job(target=target, scenario=CommandInjectionScenario())

    coord = Coordinator(storage, concurrency=1, mode="docker")
    findings = asyncio.run(coord.run([job]))
    storage.close()

    assert len(findings) == 1
    f = findings[0]
    assert f.verdict == Verdict.PROVEN, f"not proven: {f.detail}"
    assert f.evidence.get("oracle") == "child_process"
    procs = f.evidence.get("processes", [])
    assert any("id" in p for p in procs), f"command not captured: {procs}"

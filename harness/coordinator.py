"""The runner. Takes (target, scenario) jobs and runs them concurrently.

Design notes you can defend in an interview:
- Workers are stateless: each pulls a job, does it start to finish, writes a
  finding, loops. Restarting one loses nothing.
- Concurrency is bounded by a semaphore so we do not spawn a thousand
  containers at once.
- FAIL CLOSED: any exception becomes an ERROR finding, never a silent pass.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

from . import sandbox
from .client import MCPClient
from .models import Finding, Target, Verdict
from .oracle.base import Observation
from .oracle.canary import CanaryOracle
from .oracle.egress import EgressOracle
from .oracle.process import ProcessOracle
from .scenarios.base import Scenario
from .storage import Storage


@dataclass
class Job:
    target: Target
    scenario: Scenario


class Coordinator:
    def __init__(self, storage: Storage, concurrency: int = 4, mode: str = "local"):
        self._storage = storage
        self._sem = asyncio.Semaphore(concurrency)
        self._mode = mode

    async def run(self, jobs: list[Job]) -> list[Finding]:
        results = await asyncio.gather(*(self._run_one(j) for j in jobs))
        return results

    async def _run_one(self, job: Job) -> Finding:
        async with self._sem:
            handle = None
            try:
                handle = sandbox.setup(job.target, mode=self._mode)
                client = MCPClient(handle.launch, env=handle.env)
                async with client.connect() as connected:
                    outputs = await job.scenario.run(connected)
                    # collect egress/process data while the sandbox is still
                    # alive (the docker sandbox's tmpfs dies with the container).
                    # to_thread keeps the blocking `docker exec` off the loop so
                    # concurrent jobs are not stalled.
                    collected = await asyncio.to_thread(handle.collect)

                # hand observations to every registered oracle. Each watches
                # one boundary; the run is PROVEN if ANY of them fires.
                obs = Observation(
                    outputs=outputs,
                    egress=collected.get("egress", []),
                    processes=collected.get("processes", []),
                )
                oracles = [
                    CanaryOracle(handle.canary_tokens),
                    EgressOracle(),
                    ProcessOracle(),
                ]

                fired = None
                for oracle in oracles:
                    result = oracle.judge(obs)
                    if result.proven:
                        fired = (oracle, result)
                        break

                if fired is not None:
                    oracle, result = fired
                    evidence = dict(result.evidence or {})
                    evidence["oracle"] = oracle.name
                    finding = Finding(
                        target=job.target.name,
                        scenario=job.scenario.name,
                        verdict=Verdict.PROVEN,
                        detail=f"[{oracle.name}] {result.detail}",
                        evidence=evidence,
                    )
                else:
                    finding = Finding(
                        target=job.target.name,
                        scenario=job.scenario.name,
                        verdict=Verdict.NOT_PROVEN,
                    )
            except Exception as e:  # noqa: BLE001 - fail closed
                finding = Finding(
                    target=job.target.name,
                    scenario=job.scenario.name,
                    verdict=Verdict.ERROR,
                    detail=f"{type(e).__name__}: {e}",
                )
            finally:
                if handle is not None:
                    handle.cleanup()

            self._storage.save(finding)
            return finding

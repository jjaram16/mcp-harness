"""Child process oracle.

The reference server reads files; it should never shell out. The sandbox
watches for processes the server spawns. If it spawned ANY child during a
scenario, something executed code on its behalf, which is command execution
however it was reached. That is a proven violation, no per-attack verifier
required.

This oracle only judges what the sandbox captured in Observation.processes;
the capture itself lands in a later milestone, so until then the list is empty
and this oracle stays quiet.
"""
from __future__ import annotations

from .base import Oracle, Observation, OracleResult


class ProcessOracle(Oracle):
    name = "child_process"

    def judge(self, obs: Observation) -> OracleResult:
        if obs.processes:
            return OracleResult(
                proven=True,
                detail=f"Server spawned {len(obs.processes)} child process(es)",
                evidence={
                    "process_count": len(obs.processes),
                    "processes": obs.processes,
                },
            )
        return OracleResult(proven=False)

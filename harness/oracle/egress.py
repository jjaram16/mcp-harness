"""Network egress oracle.

The sandbox cuts the server off from the network and routes any outbound
attempt through a logged proxy. A server that reads files has no business
calling out. So if ANY outbound request was captured during a scenario, the
server either exfiltrated data or was tricked into a server-side request
(SSRF). Either way the boundary broke, with no per-attack verifier required.

This oracle only judges what the sandbox captured in Observation.egress; the
capture itself lands in a later milestone, so until then the list is empty and
this oracle stays quiet.
"""
from __future__ import annotations

from .base import Oracle, Observation, OracleResult


class EgressOracle(Oracle):
    name = "network_egress"

    def judge(self, obs: Observation) -> OracleResult:
        if obs.egress:
            return OracleResult(
                proven=True,
                detail=f"Server made {len(obs.egress)} outbound request(s)",
                evidence={
                    "request_count": len(obs.egress),
                    "requests": obs.egress,
                },
            )
        return OracleResult(proven=False)

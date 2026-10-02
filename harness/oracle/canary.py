"""Filesystem canary oracle.

We plant secret files OUTSIDE the server's allowed directory, each containing
a unique random token. If any token ever shows up in the server's output, the
server read a file it never should have. That is a proven file leak, with no
per-attack verifier required.
"""
from __future__ import annotations

from .base import Oracle, Observation, OracleResult


class CanaryOracle(Oracle):
    name = "filesystem_canary"

    def __init__(self, tokens: dict[str, str]):
        # token -> path it was planted at, e.g. {"CANARY_a1b2": "/etc/secret"}
        self._tokens = tokens

    def judge(self, obs: Observation) -> OracleResult:
        blob = "\n".join(obs.outputs)
        for token, planted_path in self._tokens.items():
            if token in blob:
                return OracleResult(
                    proven=True,
                    detail=f"Server leaked canary planted at {planted_path}",
                    evidence={
                        "token": token,
                        "planted_path": planted_path,
                        "leaked_output": _excerpt(blob, token),
                    },
                )
        return OracleResult(proven=False)


def _excerpt(blob: str, token: str, radius: int = 120) -> str:
    i = blob.find(token)
    start = max(0, i - radius)
    end = min(len(blob), i + len(token) + radius)
    return blob[start:end]

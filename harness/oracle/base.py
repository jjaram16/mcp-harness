"""The oracle interface.

An oracle watches ONE kind of boundary and answers a single question:
"given everything the server said and did, did my boundary break?"

Scenarios do not judge themselves. They hand their observations to the
oracles, and the oracles decide. That inversion is what lets the harness
catch violations no scenario explicitly looked for.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class Observation:
    """Everything collected during one scenario run, handed to the oracles.

    - outputs:   text the server returned from tool calls
    - egress:    outbound network attempts captured by the sandbox proxy
    - processes: child processes the sandbox saw the server spawn
    """
    outputs: list[str]
    egress: list[dict[str, Any]]
    processes: list[str]


@dataclass
class OracleResult:
    proven: bool
    detail: str = ""
    evidence: dict[str, Any] | None = None


class Oracle(ABC):
    name: str

    @abstractmethod
    def judge(self, obs: Observation) -> OracleResult:
        """Return proven=True only on a real, observed violation."""
        raise NotImplementedError

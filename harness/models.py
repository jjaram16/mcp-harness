"""Core data types passed between components.

Keeping these in one place means the coordinator, oracle, scenarios and
storage all agree on the shape of a job and a finding.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    """The only three outcomes a scenario run can have.

    PROVEN      - the oracle observed a real boundary violation
    NOT_PROVEN  - the attack ran cleanly, nothing tripped
    ERROR       - something broke; we FAIL CLOSED and never call this clean
    """
    PROVEN = "proven"
    NOT_PROVEN = "not_proven"
    ERROR = "error"


@dataclass
class Target:
    """A server to test.

    `launch` is how the sandbox starts it. For the reference server this is a
    python module; for a real server it would be its own start command.
    """
    name: str
    launch: list[str]
    allowed_dir: str = "/srv/data"   # the only dir the server SHOULD read


@dataclass
class Finding:
    """A single proven (or errored) result, with the evidence attached."""
    target: str
    scenario: str
    verdict: Verdict
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_row(self) -> dict[str, Any]:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        return d

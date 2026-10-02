"""Simple name -> object registries so the CLI stays declarative.

Add a new scenario or target here and it becomes selectable on the command
line with no other wiring.
"""
from __future__ import annotations

from .models import Target
from .scenarios.base import Scenario
from .scenarios.command_injection import CommandInjectionScenario
from .scenarios.path_traversal import PathTraversalScenario
from .scenarios.ssrf import SSRFScenario

# the deliberately vulnerable reference server you ship with the repo
REFERENCE_TARGET = Target(
    name="testserver",
    launch=["python3", "-m", "testserver.server"],
    allowed_dir="data",
)

TARGETS: dict[str, Target] = {
    REFERENCE_TARGET.name: REFERENCE_TARGET,
}

SCENARIOS: dict[str, type[Scenario]] = {
    PathTraversalScenario.name: PathTraversalScenario,
    SSRFScenario.name: SSRFScenario,
    CommandInjectionScenario.name: CommandInjectionScenario,
}


def all_scenarios() -> list[Scenario]:
    return [cls() for cls in SCENARIOS.values()]

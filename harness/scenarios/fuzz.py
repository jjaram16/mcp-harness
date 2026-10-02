"""Fuzzing scenario.

Same "send, don't judge" contract as every other scenario, but instead of a
fixed payload list it fires a CORPUS: the hand-written path-traversal seeds
PLUS a batch of mutated variations from the Mutator. Seeding the corpus with
the originals (as real fuzzers do) guarantees coverage never regresses below
the fixed run, while the mutations reach cases nobody hand-wrote.

It is deterministic: (iterations, seed) fully determine which payloads are
sent, so a fuzz finding reproduces exactly on a rerun with the same --seed.
"""
from __future__ import annotations

from .base import Scenario
from .path_traversal import FILE_HINTS, PAYLOADS, _first_string_arg
from ..client import MCPClient
from ..fuzzer import Mutator


class FuzzScenario(Scenario):
    name = "fuzz_path_traversal"

    def __init__(self, iterations: int = 25, seed: int = 0):
        self.iterations = iterations
        self.seed = seed

    def corpus(self) -> list[str]:
        """Seeds + deterministic mutations. Exposed so tests can inspect it."""
        mutations = Mutator(self.seed).generate(list(PAYLOADS), self.iterations)
        return list(PAYLOADS) + mutations

    async def run(self, client: MCPClient) -> list[str]:
        outputs: list[str] = []
        tools = await client.list_tools()

        # Only fuzz file-reading tools: firing traversal payloads at a
        # command/URL tool would be noise, not a traversal test.
        targets = [t for t in tools if any(h in t.name.lower() for h in FILE_HINTS)]
        payloads = self.corpus()

        for tool in targets:
            arg_name = _first_string_arg(tool)
            if arg_name is None:
                continue
            for payload in payloads:
                try:
                    outputs.append(await client.call_tool(tool.name, {arg_name: payload}))
                except Exception as e:  # noqa: BLE001 - a crash is also data
                    outputs.append(f"[call error on {tool.name}: {e}]")
        return outputs

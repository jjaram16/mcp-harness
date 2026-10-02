"""Path traversal scenario.

Looks for any tool that smells like it reads files, then calls it with a
batch of traversal payloads trying to escape the allowed directory and reach
a planted canary. It does NOT check the result. If a canary leaked, the
CanaryOracle will see it.
"""
from __future__ import annotations

from .base import Scenario
from ..client import MCPClient

# A spread of classic escape payloads. They blindly aim at a canary filename
# the sandbox plants just outside the allowed dir, plus common system paths
# the docker sandbox will plant at later. The oracle catches whichever lands.
CANARY_NAME = "secret_canary"
PAYLOADS = [
    f"../{CANARY_NAME}",
    f"../../{CANARY_NAME}",
    f"../../../{CANARY_NAME}",
    f"..%2f{CANARY_NAME}",
    f"....//{CANARY_NAME}",
    f"/etc/{CANARY_NAME}",            # for the future docker sandbox
    f"../../../../etc/{CANARY_NAME}",
]

# crude heuristic for "this tool probably touches files"
FILE_HINTS = ("file", "read", "path", "open", "cat", "load", "document")


class PathTraversalScenario(Scenario):
    name = "path_traversal"

    async def run(self, client: MCPClient) -> list[str]:
        outputs: list[str] = []
        tools = await client.list_tools()

        targets = [t for t in tools if any(h in t.name.lower() for h in FILE_HINTS)]
        # if nothing obvious matched, try everything with a single string arg
        if not targets:
            targets = tools

        for tool in targets:
            arg_name = _first_string_arg(tool)
            if arg_name is None:
                continue
            for payload in PAYLOADS:
                try:
                    result = await client.call_tool(tool.name, {arg_name: payload})
                    outputs.append(result)
                except Exception as e:  # noqa: BLE001 - a crash is also data
                    outputs.append(f"[call error on {tool.name}: {e}]")
        return outputs


def _first_string_arg(tool) -> str | None:
    """Pull the first string parameter name out of a tool's input schema."""
    schema = getattr(tool, "inputSchema", None) or {}
    props = schema.get("properties", {})
    for name, spec in props.items():
        if spec.get("type", "string") == "string":
            return name
    # fall back to the first property of any type
    return next(iter(props), None)

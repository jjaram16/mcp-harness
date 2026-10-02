"""Command injection scenario.

Finds any tool that smells like it runs commands and feeds it a benign marker
command. It does NOT inspect the output: if the server actually spawned a
child to run it, the ProcessOracle sees the process strace captured, and that
is the proof. The payload is harmless (`id`) -- that it RAN at all is the
violation, not what it does.
"""
from __future__ import annotations

from .base import Scenario
from .path_traversal import _first_string_arg
from ..client import MCPClient

CMD_PAYLOAD = "id"
CMD_HINTS = ("command", "cmd", "exec", "run", "shell", "spawn", "system")


class CommandInjectionScenario(Scenario):
    name = "command_injection"

    async def run(self, client: MCPClient) -> list[str]:
        outputs: list[str] = []
        tools = await client.list_tools()

        targets = [t for t in tools if any(h in t.name.lower() for h in CMD_HINTS)]
        for tool in targets:
            arg_name = _first_string_arg(tool)
            if arg_name is None:
                continue
            try:
                outputs.append(
                    await client.call_tool(tool.name, {arg_name: CMD_PAYLOAD})
                )
            except Exception as e:  # noqa: BLE001 - a crash is also data
                outputs.append(f"[call error on {tool.name}: {e}]")
        return outputs

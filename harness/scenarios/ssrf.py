"""SSRF scenario.

Finds any tool that smells like it fetches URLs and points it at an
attacker-style URL. It does NOT inspect the response: if the server made the
outbound connection at all, the EgressOracle sees the attempt in the
strace-captured egress, and that is the proof.

The destination is 192.0.2.1, an RFC 5737 TEST-NET-1 address reserved for
documentation and guaranteed never routed on the real internet. So the attempt
is inert whether it runs in the docker sandbox (where --network none drops it
anyway) or, by accident, unsandboxed -- while still proving the server will
connect wherever it is told. A real engagement would aim this at 169.254.169.254
(cloud metadata) or an internal host; the proof mechanism is identical.
"""
from __future__ import annotations

from .base import Scenario
from .path_traversal import _first_string_arg
from ..client import MCPClient

SSRF_URL = "http://192.0.2.1:80/latest/meta-data/"
URL_HINTS = ("url", "fetch", "http", "request", "curl")


class SSRFScenario(Scenario):
    name = "ssrf"

    async def run(self, client: MCPClient) -> list[str]:
        outputs: list[str] = []
        tools = await client.list_tools()

        targets = [t for t in tools if any(h in t.name.lower() for h in URL_HINTS)]
        for tool in targets:
            arg_name = _first_string_arg(tool)
            if arg_name is None:
                continue
            try:
                outputs.append(
                    await client.call_tool(tool.name, {arg_name: SSRF_URL})
                )
            except Exception as e:  # noqa: BLE001 - a crash is also data
                outputs.append(f"[call error on {tool.name}: {e}]")
        return outputs

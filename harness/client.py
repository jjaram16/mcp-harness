"""The attacker: a bare MCP client, no LLM behind it.

Wraps the MCP Python SDK's stdio transport so scenarios get two simple calls:
list_tools() and call_tool(). The server believes it is talking to a normal
AI client; really it is talking to our payloads.

Two things learned the hard way and baked in here:

1. stdio_client and ClientSession set up anyio cancel scopes. They must be
   entered and exited inside the SAME task and frame, so we expose one inline
   connect() context manager instead of spanning __aenter__/__aexit__ with an
   AsyncExitStack (that raised "exit cancel scope in a different task").

2. A stdio subprocess does NOT inherit the parent environment by default, so we
   pass env through explicitly. That is how the server under test receives its
   allowed directory.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class MCPClient:
    def __init__(self, launch: list[str], env: dict[str, str] | None = None):
        self._launch = launch
        self._env = env
        self._session: ClientSession | None = None

    @asynccontextmanager
    async def connect(self):
        params = StdioServerParameters(
            command=self._launch[0],
            args=self._launch[1:],
            env=self._env,
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                self._session = session
                try:
                    yield self
                finally:
                    self._session = None

    async def list_tools(self) -> list[Any]:
        assert self._session is not None
        resp = await self._session.list_tools()
        return list(resp.tools)

    async def call_tool(self, name: str, arguments: dict) -> str:
        assert self._session is not None
        resp = await self._session.call_tool(name, arguments)
        parts: list[str] = []
        for block in resp.content:
            text = getattr(block, "text", None)
            parts.append(text if text is not None else str(block))
        return "\n".join(parts)

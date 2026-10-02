"""Scenario interface.

A scenario is deliberately dumb: it knows how to SEND an attack, not how to
judge it. It enumerates the server's tools, picks ones worth attacking, fires
payloads, and returns the raw outputs. The oracles decide what it means.

This split keeps scenarios tiny and makes adding a new attack class cheap.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..client import MCPClient


class Scenario(ABC):
    name: str

    @abstractmethod
    async def run(self, client: MCPClient) -> list[str]:
        """Attack the connected server. Return the raw text it gave back."""
        raise NotImplementedError

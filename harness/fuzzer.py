"""Payload mutator: turns a few seed payloads into many variations.

Fixed payload lists only catch bugs someone already thought of. The mutator
takes those seeds and warps them -- re-encoding, swapping separators, changing
traversal depth, injecting null bytes, flipping case, wrapping with redundant
path noise -- so the harness also fires payloads nobody hand-wrote. One of
those warped payloads can slip past a filter a hand-written list walked right
into, and trip a tripwire for an unplanned bug.

Determinism: every random choice comes from a single seeded random.Random, and
the transforms use only its stable primitives (random/randint/choice), so a
given (seed, iterations) always yields the exact same payloads. Rerun with the
same --seed to reproduce a finding precisely.

The mutator is generic: it warps any list of string seeds, so the same engine
fuzzes path-traversal, SSRF and command-injection corpora alike.
"""
from __future__ import annotations

import random
from typing import Callable
from urllib.parse import quote

# Each transform takes (payload, rng) -> mutated payload. They are intentionally
# small and composable; mutate_one() applies a random subset of them.


def _url_encode(s: str, rng: random.Random) -> str:
    return quote(s, safe="")


def _double_encode(s: str, rng: random.Random) -> str:
    return quote(quote(s, safe=""), safe="")


def _mixed_encode(s: str, rng: random.Random) -> str:
    # percent-encode a random subset of characters, leave the rest raw
    return "".join(quote(c, safe="") if rng.random() < 0.5 else c for c in s)


def _separator_swap(s: str, rng: random.Random) -> str:
    # swap forward slashes for backslashes (Windows-style / filter-confusion)
    return "".join("\\" if (c == "/" and rng.random() < 0.7) else c for c in s)


def _depth_change(s: str, rng: random.Random) -> str:
    # prepend extra traversal levels
    return "../" * rng.randint(1, 4) + s


def _null_byte(s: str, rng: random.Random) -> str:
    # classic null-byte injection, raw or encoded, at a random position
    pos = rng.randint(0, len(s))
    token = rng.choice(["\x00", "%00"])
    return s[:pos] + token + s[pos:]


def _case_change(s: str, rng: random.Random) -> str:
    return "".join(c.upper() if (c.isalpha() and rng.random() < 0.5) else c for c in s)


def _wrap(s: str, rng: random.Random) -> str:
    # wrap in redundant path noise that normalizes away, or trailing junk
    prefix = rng.choice(["./", "/", "", "x/../", "./././", " "])
    suffix = rng.choice(["", "/", "/.", "%20", "#"])
    return prefix + s + suffix


_TRANSFORMS: list[Callable[[str, random.Random], str]] = [
    _url_encode,
    _double_encode,
    _mixed_encode,
    _separator_swap,
    _depth_change,
    _null_byte,
    _case_change,
    _wrap,
]


class Mutator:
    """Deterministic payload mutator driven by a single seeded RNG."""

    def __init__(self, seed: int = 0):
        self._rng = random.Random(seed)

    def mutate_one(self, payload: str) -> str:
        """Apply a random, non-empty subset of transforms (in fixed order)."""
        chosen = [t for t in _TRANSFORMS if self._rng.random() < 0.35]
        if not chosen:
            chosen = [self._rng.choice(_TRANSFORMS)]
        out = payload
        for transform in chosen:
            out = transform(out, self._rng)
        return out

    def generate(self, seeds: list[str], n: int) -> list[str]:
        """Return up to n DISTINCT mutations of the seeds (never a raw seed).

        Deterministic for a given constructor seed: the same (seed, seeds, n)
        always produces the same list. Stops early if the transform space is
        too small to reach n distinct results rather than spinning forever.
        """
        seed_list = list(seeds)
        if not seed_list or n <= 0:
            return []
        seed_set = set(seed_list)
        out: list[str] = []
        seen: set[str] = set()
        attempts = 0
        limit = n * 80
        while len(out) < n and attempts < limit:
            attempts += 1
            mut = self.mutate_one(self._rng.choice(seed_list))
            if not mut or mut in seed_set or mut in seen:
                continue
            seen.add(mut)
            out.append(mut)
        return out

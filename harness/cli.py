"""Command line entry point.

    harness run --target testserver [--mode local|docker] [--concurrency N]
    harness report [--limit N]
"""
from __future__ import annotations

import argparse
import asyncio
import sys

from . import registry
from .coordinator import Coordinator, Job
from .storage import open_storage


def _cmd_run(args) -> int:
    if args.target not in registry.TARGETS:
        print(f"unknown target: {args.target}", file=sys.stderr)
        print(f"known: {', '.join(registry.TARGETS)}", file=sys.stderr)
        return 2

    target = registry.TARGETS[args.target]
    scenarios = registry.all_scenarios()
    if args.fuzz_iterations > 0:
        # fuzzing is on by default; --fuzz-iterations 0 turns it off
        from .scenarios.fuzz import FuzzScenario
        scenarios.append(
            FuzzScenario(iterations=args.fuzz_iterations, seed=args.seed)
        )
    jobs = [Job(target=target, scenario=s) for s in scenarios]

    storage = open_storage(args.db)
    coord = Coordinator(storage, concurrency=args.concurrency, mode=args.mode)
    findings = asyncio.run(coord.run(jobs))

    proven = [f for f in findings if f.verdict.value == "proven"]
    errored = [f for f in findings if f.verdict.value == "error"]

    for f in findings:
        mark = {"proven": "[PROVEN]", "not_proven": "[clean] ", "error": "[ERROR] "}[
            f.verdict.value
        ]
        print(f"{mark} {f.target}/{f.scenario}  {f.detail}")

    storage.close()
    print(
        f"\n{len(proven)} proven, {len(errored)} errored, "
        f"{len(findings)} total. See `harness report` for evidence."
    )
    # proven findings are the point, so a clean run exits non-zero in CI only
    # if you want that; here proven == success of the harness itself
    return 0


def _cmd_report(args) -> int:
    storage = open_storage(args.db)
    rows = storage.recent(limit=args.limit)
    if not rows:
        print("no findings yet. run `harness run --target testserver` first.")
    for r in rows:
        print(f"#{r['id']} [{r['verdict']}] {r['target']}/{r['scenario']}")
        if r["detail"]:
            print(f"    {r['detail']}")
        if r["evidence"]:
            leaked = r["evidence"].get("leaked_output")
            if leaked:
                print(f"    evidence: ...{leaked.strip()}...")
    storage.close()
    return 0


def main() -> None:
    p = argparse.ArgumentParser(prog="harness")
    p.add_argument("--db", default="harness.db", help="sqlite path")
    sub = p.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("run", help="run scenarios against a target")
    pr.add_argument("--target", required=True)
    pr.add_argument("--mode", default="local", choices=["local", "docker"])
    pr.add_argument("--concurrency", type=int, default=4)
    pr.add_argument(
        "--fuzz-iterations", type=int, default=25,
        help="mutated payloads per fuzz scenario (0 disables fuzzing)",
    )
    pr.add_argument(
        "--seed", type=int, default=0,
        help="RNG seed for the fuzzer; same seed reproduces the same payloads",
    )
    pr.set_defaults(func=_cmd_run)

    prep = sub.add_parser("report", help="show recent findings")
    prep.add_argument("--limit", type=int, default=50)
    prep.set_defaults(func=_cmd_report)

    args = p.parse_args()
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()

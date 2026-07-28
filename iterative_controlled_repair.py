#!/usr/bin/env python3
"""Iterative DFixer-style repair loop for controlled authoritative labs."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from dataclasses import dataclass
from pathlib import Path

import controlled_zone_repair
import dnsviz_grok_adapter
import dnssec_lab
import dnssec_repair_engine as repair


@dataclass(frozen=True)
class IterationRecord:
    iteration: int
    grok: str
    codes_before: tuple[str, ...]
    selected_code: str | None
    repair_family: str | None
    actions: tuple[str, ...]
    codes_after: tuple[str, ...] | None = None


@dataclass(frozen=True)
class IterativeRepairResult:
    backend: str
    converged: bool
    iterations: tuple[IterationRecord, ...]
    final_codes: tuple[str, ...]


def run_diagnose(backend: str, prefix: str) -> Path:
    if backend == "bind9":
        dnssec_lab.dnsviz(prefix)
    else:
        # PowerDNS uses the same DNSViz runner after its services are started.
        dnssec_lab.dnsviz(prefix)
    return dnssec_lab.OUT / f"{prefix}.grok.json"


def current_codes(grok: Path, backend: str) -> tuple[str, ...]:
    diagnosis = dnsviz_grok_adapter.diagnose_grok(grok, backend)
    return diagnosis.error_codes


def execute_one_topological_repair(backend: str, grok: Path, *, rotate_keys: bool) -> tuple[repair.RepairPlan, controlled_zone_repair.ControlledRepairResult]:
    diagnosis = dnsviz_grok_adapter.diagnose_grok(grok, backend)
    plan = repair.build_topological_plan(diagnosis.to_context())
    result = controlled_zone_repair.repair_lab_from_grok(backend, grok, rotate_keys=rotate_keys, topological=True)
    return plan, result


def iterative_repair(
    backend: str,
    *,
    max_iterations: int = 5,
    prefix: str = "iterative-repair",
    keep_keys: bool | None = None,
    rotate_keys: bool = False,
) -> IterativeRepairResult:
    backend = repair.normalize_backend(backend)
    if keep_keys is not None:
        rotate_keys = not keep_keys
    records: list[IterationRecord] = []
    final_codes: tuple[str, ...] = ()

    for iteration in range(1, max_iterations + 1):
        before_grok = run_diagnose(backend, f"{prefix}.{iteration}.before")
        codes_before = current_codes(before_grok, backend)
        if not codes_before:
            final_codes = ()
            return IterativeRepairResult(backend=backend, converged=True, iterations=tuple(records), final_codes=final_codes)

        plan, repair_result = execute_one_topological_repair(backend, before_grok, rotate_keys=rotate_keys)
        selected_code = plan.codes[0] if plan.codes else None
        repair_family = plan.instructions[0].family if plan.instructions else None

        after_grok = run_diagnose(backend, f"{prefix}.{iteration}.after")
        codes_after = current_codes(after_grok, backend)
        records.append(
            IterationRecord(
                iteration=iteration,
                grok=str(before_grok),
                codes_before=codes_before,
                selected_code=selected_code,
                repair_family=repair_family,
                actions=repair_result.actions,
                codes_after=codes_after,
            )
        )
        final_codes = codes_after
        if not codes_after:
            return IterativeRepairResult(backend=backend, converged=True, iterations=tuple(records), final_codes=())

    return IterativeRepairResult(backend=backend, converged=False, iterations=tuple(records), final_codes=final_codes)


def main() -> None:
    parser = argparse.ArgumentParser(description="Iteratively repair controlled DNSSEC labs using DNSViz grok feedback.")
    parser.add_argument("--backend", choices=sorted(repair.BACKENDS), required=True)
    parser.add_argument("--max-iterations", type=int, default=5)
    parser.add_argument("--prefix", default="iterative-repair")
    parser.add_argument("--rotate-keys", action="store_true")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()

    result = iterative_repair(
        args.backend,
        max_iterations=args.max_iterations,
        prefix=args.prefix,
        rotate_keys=args.rotate_keys,
    )
    text = json.dumps(asdict(result), ensure_ascii=False, indent=2) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
    print(text, end="")
    if not result.converged:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

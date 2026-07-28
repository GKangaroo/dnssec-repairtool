#!/usr/bin/env python3
"""One-click repair executor for controlled parent+child authoritative labs.

This module targets the project goal where the operator controls both the child
zone and its parent zone. Given DNSViz grok output, it builds a DFixer-style
plan and applies the plan through a backend adapter. The adapter operates on the
current zone backend and preserves business records in unsigned zones.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from dataclasses import dataclass
from pathlib import Path

import dnsviz_grok_adapter
import dnssec_repair_engine as repair
import zone_backend_adapter


@dataclass(frozen=True)
class ControlledRepairResult:
    backend: str
    grok: str
    zone: str
    parent_zone: str
    codes: tuple[str, ...]
    rotate_keys: bool
    plan: dict
    actions: tuple[str, ...]


def repair_backend_from_grok(backend: str, grok: Path, *, rotate_keys: bool = False, topological: bool = False) -> ControlledRepairResult:
    backend = repair.normalize_backend(backend)
    diagnosis = dnsviz_grok_adapter.diagnose_grok(grok, backend)
    if topological:
        plan = repair.build_topological_plan(diagnosis.to_context())
    else:
        plan = repair.build_plan(diagnosis.to_context())
    adapter = zone_backend_adapter.adapter_for_backend(backend, rotate_keys=rotate_keys)
    result = adapter.execute_plan(plan)
    adapter.refresh()
    # adapter.refresh() appends to adapter.actions after BackendRepairResult was
    # created, so use adapter.actions as the authoritative action trace.
    actions = tuple(adapter.actions)
    return ControlledRepairResult(
        backend=backend,
        grok=str(grok),
        zone=diagnosis.zone,
        parent_zone=diagnosis.parent_zone or "",
        codes=plan.codes,
        rotate_keys=rotate_keys,
        plan=repair.plan_as_dict(plan),
        actions=actions,
    )


def repair_bind9_lab_from_grok(grok: Path, *, rotate_keys: bool = False, topological: bool = False) -> ControlledRepairResult:
    return repair_backend_from_grok("bind9", grok, rotate_keys=rotate_keys, topological=topological)


def repair_powerdns_lab_from_grok(grok: Path, *, rotate_keys: bool = False, topological: bool = False) -> ControlledRepairResult:
    return repair_backend_from_grok("powerdns", grok, rotate_keys=rotate_keys, topological=topological)


def repair_lab_from_grok(backend: str, grok: Path, *, reset_keys: bool | None = None, rotate_keys: bool | None = None, topological: bool = False) -> ControlledRepairResult:
    if rotate_keys is None:
        rotate_keys = bool(reset_keys) if reset_keys is not None else False
    return repair_backend_from_grok(backend, grok, rotate_keys=rotate_keys, topological=topological)


def _legacy_rebuild_powerdns_lab_from_grok(grok: Path, *, reset_keys: bool = True) -> ControlledRepairResult:
    """Deprecated compatibility path kept only for old experiments."""
    import dnssec_lab
    import powerdns_lab

    diagnosis = dnsviz_grok_adapter.diagnose_grok(grok, "powerdns")
    plan = repair.build_plan(diagnosis.to_context())
    actions = []
    if reset_keys:
        dnssec_lab.reset_keys("example")
        dnssec_lab.reset_keys("com")
        actions.append("reset child and parent DNSSEC keys")
    dnssec_lab.build_zones("good")
    actions.append("rebuild clean child/parent/root signed zones")
    powerdns_lab.stop(quiet=True)
    powerdns_lab.write_pdns_bind_configs()
    powerdns_lab.write_pdns_dnssec_metadata()
    resolver = dnssec_lab.CONF / "named-resolver.conf"
    resolver.write_text(dnssec_lab.named_conf_resolver(), encoding="ascii")
    powerdns_lab.start()
    actions.append("refresh PowerDNS bind backend metadata and restart services")
    return ControlledRepairResult(
        backend="powerdns",
        grok=str(grok),
        zone=diagnosis.zone,
        parent_zone=diagnosis.parent_zone or "",
        codes=plan.codes,
        rotate_keys=reset_keys,
        plan=repair.plan_as_dict(plan),
        actions=tuple(actions),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="One-click controlled parent+child repair from DNSViz grok JSON.")
    parser.add_argument("--backend", choices=sorted(repair.BACKENDS), required=True)
    parser.add_argument("--grok", type=Path, required=True)
    parser.add_argument("--rotate-keys", action="store_true", help="force child/parent key rotation before repair")
    parser.add_argument("--topological", action="store_true", help="execute only the current top-priority repair family")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()

    result = repair_lab_from_grok(args.backend, args.grok, rotate_keys=args.rotate_keys, topological=args.topological)
    data = asdict(result)
    text = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
    print(text, end="")


if __name__ == "__main__":
    main()

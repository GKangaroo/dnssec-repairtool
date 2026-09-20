#!/usr/bin/env python3
"""DFixer-style repair planner and demo executors for the local DNSSEC lab.

This module intentionally separates three layers:

1. diagnosis context: scenario, backend and observed DNSViz codes;
2. repair planning: map codes to a repair family and backend action;
3. execution: apply the repair through a backend-specific demo executor.

The current executors target the reproducible BIND9/PowerDNS labs. Production
executors should implement the same small interface with real zone/backend APIs.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from dnssec_scenarios import get as get_scenario
from dnssec_scenarios import names as scenario_names

import dnssec_repair_catalog as catalog


BACKENDS = {"bind9", "powerdns"}


@dataclass(frozen=True)
class DiagnosisContext:
    backend: str
    scenario: str
    expected_codes: tuple[str, ...]
    observed_codes: tuple[str, ...] = ()
    zone: str = "example.com."
    parent_zone: str = "com."


@dataclass(frozen=True)
class RepairInstruction:
    backend: str
    scenario: str
    code: str
    family: str
    executor: str
    required_permission: str
    action: str
    demo_action: str
    note: str


@dataclass(frozen=True)
class RepairPlan:
    backend: str
    scenario: str
    zone: str
    parent_zone: str
    instructions: tuple[RepairInstruction, ...]

    @property
    def codes(self) -> tuple[str, ...]:
        return tuple(instruction.code for instruction in self.instructions)


GENERIC_CODE_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("cds_cdnskey_multi_signal", ("CDS_", "CDNSKEY_", "MULTIPLE_CDS", "MULTIPLE_CDNSKEY")),
    ("multi_auth_dnskey_sync", ("DNSKEY_MISSING_FROM_SERVERS",)),
    ("dnskey_rrset_cleanup", ("DNSKEY_BAD_LENGTH", "DNSKEY_ZERO_LENGTH", "DNSKEY_NOT_AT_ZONE_APEX")),
    ("revoked_key_lifecycle", ("REVOKED_NOT_SIGNING", "DNSKEY_REVOKED_DS", "DNSKEY_REVOKED_RRSIG")),
    ("ds_rrset_repair", ("DIGEST_INVALID", "DIGEST_ALGORITHM_NOT_SUPPORTED", "DIGEST_ALGORITHM_PROHIBITED", "DS_DIGEST_ALGORITHM")),
    ("inactive_digest_policy", ("DIGEST_ALGORITHM_NOT_RECOMMENDED", "DIGEST_ALGORITHM_VALIDATION_PROHIBITED")),
    ("key_chain_repair", ("MISSING_SEP_FOR_ALG", "NO_SEP")),
    ("signature_resign", ("MISSING_RRSIG", "SIGNATURE_INVALID", "SIGNER_NOT_ZONE", "RRSIG_LABELS_EXCEED")),
    ("parent_ds_response_behavior", ("REFERRAL_FOR_DS_QUERY",)),
    ("delegation_nsec_bitmap", ("REFERRAL_WITHOUT_NS", "REFERRAL_WITH_DS", "REFERRAL_WITH_SOA")),
    ("nsec_nsec3_regenerate", ("NSEC", "SNAME", "STYPE", "WILDCARD", "EXISTING_NAME", "EXISTING_TYPE", "OPT_OUT")),
    ("ttl_resign", ("TTL", "EXPIRATION", "INCEPTION", "ORIGINAL_TTL")),
    ("rrsig_bad_length", ("RRSIG_BAD_LENGTH",)),
    ("unsupported_or_legacy_algorithm", ("ALGORITHM_",)),
)


DEPENDENT_CODES = {
    "MISSING_RRSIG_FOR_ALG_DS",
    "NO_SEP",
    "REVOKED_NOT_SIGNING",
}


TOPOLOGICAL_CODE_ORDER = (
    "DNSKEY_MISSING_FROM_SERVERS",
    "DNSKEY_REVOKED_DS",
    "DNSKEY_REVOKED_RRSIG",
    "DNSKEY_BAD_LENGTH_ECDSA256",
    "DNSKEY_BAD_LENGTH_ECDSA384",
    "DNSKEY_BAD_LENGTH_ED25519",
    "DNSKEY_BAD_LENGTH_ED448",
    "DNSKEY_BAD_LENGTH_GOST",
    "DNSKEY_ZERO_LENGTH",
    "DNSKEY_NOT_AT_ZONE_APEX",
    "MISSING_RRSIG_FOR_ALG_DNSKEY",
    "DIGEST_INVALID",
    "DIGEST_ALGORITHM_NOT_SUPPORTED",
    "DIGEST_ALGORITHM_PROHIBITED",
    "DS_DIGEST_ALGORITHM_IGNORED",
    "DS_DIGEST_ALGORITHM_MAYBE_IGNORED",
    "MISSING_SEP_FOR_ALG",
    "MISSING_RRSIG",
    "SIGNATURE_INVALID",
    "RRSIG_BAD_LENGTH_ECDSA256",
    "RRSIG_BAD_LENGTH_ECDSA384",
    "RRSIG_BAD_LENGTH_ED25519",
    "RRSIG_BAD_LENGTH_ED448",
    "RRSIG_BAD_LENGTH_GOST",
    "SIGNER_NOT_ZONE",
    "RRSIG_LABELS_EXCEED_RRSET_OWNER_LABELS",
    "INCEPTION_IN_FUTURE",
    "INCEPTION_WITHIN_CLOCK_SKEW",
    "EXPIRATION_IN_PAST",
    "EXPIRATION_WITHIN_CLOCK_SKEW",
    "TTL_BEYOND_EXPIRATION",
    "ORIGINAL_TTL_EXCEEDED",
    "ORIGINAL_TTL_EXCEEDED_RRSET",
    "ORIGINAL_TTL_EXCEEDED_RRSIG",
    "RRSET_TTL_MISMATCH",
    "NONEMPTY_NSEC3_SALT",
    "NONZERO_NSEC3_ITERATION_COUNT",
    "LAST_NSEC_NEXT_NOT_ZONE",
    "NO_CLOSEST_ENCLOSER",
    "NO_NSEC3_MATCHING_SNAME",
    "NO_NSEC_MATCHING_SNAME",
    "NEXT_CLOSEST_ENCLOSER_NOT_COVERED",
    "INVALID_NSEC3_HASH",
    "INVALID_NSEC3_OWNER_NAME",
    "OPT_OUT_FLAG_NOT_SET",
    "EXISTING_NAME_COVERED",
    "EXISTING_TYPE_NOT_IN_BITMAP",
    "REFERRAL_WITHOUT_NS",
    "REFERRAL_WITH_DS",
    "REFERRAL_WITH_SOA",
    "SNAME_COVERED",
    "SNAME_NOT_COVERED",
    "STYPE_IN_BITMAP",
    "UNSUPPORTED_NSEC3_ALGORITHM",
    "WILDCARD_COVERED",
    "WILDCARD_EXPANSION_INVALID",
    "WILDCARD_NOT_COVERED",
    "CDS_DELETE_MULTIPLE_RECORDS",
    "CDS_INCORRECT_DELETE_VALUES",
    "CDS_INCONSISTENT_WITH_DS",
    "CDS_SIGNER_INVALID",
    "CDNSKEY_DELETE_MULTIPLE_RECORDS",
    "CDNSKEY_INCORRECT_DELETE_VALUES",
    "CDNSKEY_INCONSISTENT_WITH_DS",
    "CDNSKEY_INCONSISTENT_WITH_CDS",
    "CDNSKEY_SIGNER_INVALID",
    "MULTIPLE_CDS",
    "MULTIPLE_CDNSKEY",
    "ALGORITHM_NOT_RECOMMENDED",
    "ALGORITHM_NOT_SUPPORTED",
    "ALGORITHM_PROHIBITED",
    "ALGORITHM_VALIDATION_PROHIBITED",
    "NO_TRUST_ANCHOR_SIGNING",
)

TOPOLOGICAL_INDEX = {code: index for index, code in enumerate(TOPOLOGICAL_CODE_ORDER)}


def normalize_backend(backend: str) -> str:
    normalized = backend.lower()
    if normalized not in BACKENDS:
        raise ValueError(f"unsupported backend: {backend}")
    return normalized


def parse_codes(codes: str | Iterable[str] | None) -> tuple[str, ...]:
    if codes is None:
        return ()
    if isinstance(codes, str):
        if codes in {"", "<none>", "<missing>"}:
            return ()
        return tuple(item.strip() for item in codes.split(",") if item.strip())
    return tuple(item for item in codes if item)


def pick_topological_code(codes: Iterable[str], ignored_codes: Iterable[str] = ()) -> str | None:
    present = [code for code in codes if code and code not in set(ignored_codes)]
    if not present:
        return None
    independent = [code for code in present if code not in DEPENDENT_CODES]
    candidates = independent or present
    return sorted(candidates, key=lambda code: (TOPOLOGICAL_INDEX.get(code, 10_000), code))[0]


def context_from_scenario(backend: str, scenario: str, observed_codes: str | Iterable[str] | None = None) -> DiagnosisContext:
    import dnssec_lab

    backend = normalize_backend(backend)
    config = get_scenario(scenario)
    if config is None:
        raise ValueError(f"unknown scenario: {scenario}")
    return DiagnosisContext(
        backend=backend,
        scenario=scenario,
        expected_codes=tuple(config.expected_codes),
        observed_codes=parse_codes(observed_codes),
        zone=dnssec_lab.AUTH["example"]["zone"],
        parent_zone=dnssec_lab.AUTH["com"]["zone"],
    )


def _generic_group_for_code(code: str) -> str:
    for group, prefixes in GENERIC_CODE_GROUPS:
        if any(code.startswith(prefix) or code == prefix for prefix in prefixes):
            return group
    return "nsec_nsec3_regenerate" if "NSEC" in code else "ttl_resign"


def _plan_for_code(code: str):
    plan = catalog.get_repair_plan(code)
    if plan is not None:
        return plan
    group = _generic_group_for_code(code)
    return catalog.GROUP_PLANS[group]


def build_plan(context: DiagnosisContext) -> RepairPlan:
    codes = context.observed_codes or context.expected_codes
    instructions = []
    for code in codes:
        plan = _plan_for_code(code)
        if context.scenario == "wild-grok":
            demo_action = "野生 DNSViz 输入只生成结构化计划；自动执行需要真实 backend adapter 和写权限。"
        else:
            demo_action = (
                "调用 dnssec_lab.fix(scenario)，重建 clean zone、重签并重启 BIND9 lab。"
                if context.backend == "bind9"
                else "调用 powerdns_lab.fix(scenario)，重建 clean zone、重签并重建 PowerDNS DNSSEC metadata。"
            )
        instructions.append(
            RepairInstruction(
                backend=context.backend,
                scenario=context.scenario,
                code=code,
                family=plan.group,
                executor=plan.executor,
                required_permission=plan.required_permission,
                action=plan.action,
                demo_action=demo_action,
                note=plan.dfixer_logic or plan.powerdns_note,
            )
        )
    return RepairPlan(
        backend=context.backend,
        scenario=context.scenario,
        zone=context.zone,
        parent_zone=context.parent_zone,
        instructions=tuple(instructions),
    )


def build_topological_plan(context: DiagnosisContext, ignored_codes: Iterable[str] = ()) -> RepairPlan:
    codes = context.observed_codes or context.expected_codes
    top_code = pick_topological_code(codes, ignored_codes)
    if top_code is None:
        return RepairPlan(
            backend=context.backend,
            scenario=context.scenario,
            zone=context.zone,
            parent_zone=context.parent_zone,
            instructions=(),
        )
    narrowed = DiagnosisContext(
        backend=context.backend,
        scenario=context.scenario,
        expected_codes=(top_code,),
        observed_codes=(top_code,),
        zone=context.zone,
        parent_zone=context.parent_zone,
    )
    return build_plan(narrowed)


class DemoRepairExecutor:
    backend: str

    def execute(self, plan: RepairPlan) -> None:
        if plan.backend != self.backend:
            raise ValueError(f"plan backend {plan.backend} cannot be executed by {self.backend}")
        self._execute(plan.scenario)

    def _execute(self, scenario: str) -> None:
        raise NotImplementedError


class Bind9DemoExecutor(DemoRepairExecutor):
    backend = "bind9"

    def _execute(self, scenario: str) -> None:
        import dnssec_lab

        dnssec_lab.apply_scenario_fix(scenario)


class PowerDNSDemoExecutor(DemoRepairExecutor):
    backend = "powerdns"

    def _execute(self, scenario: str) -> None:
        import powerdns_lab

        powerdns_lab.apply_scenario_fix(scenario)


def executor_for_backend(backend: str) -> DemoRepairExecutor:
    backend = normalize_backend(backend)
    if backend == "bind9":
        return Bind9DemoExecutor()
    return PowerDNSDemoExecutor()


def plan_scenario(backend: str, scenario: str, observed_codes: str | Iterable[str] | None = None) -> RepairPlan:
    return build_plan(context_from_scenario(backend, scenario, observed_codes))


def execute_scenario_repair(backend: str, scenario: str, observed_codes: str | Iterable[str] | None = None) -> RepairPlan:
    plan = plan_scenario(backend, scenario, observed_codes)
    executor_for_backend(backend).execute(plan)
    return plan


def plan_as_dict(plan: RepairPlan) -> dict:
    data = asdict(plan)
    data["codes"] = list(plan.codes)
    return data


def write_plan(plan: RepairPlan, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(plan_as_dict(plan), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="DFixer-style DNSSEC repair planner for local BIND9/PowerDNS demos.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("plan")
    p.add_argument("--backend", choices=sorted(BACKENDS), required=True)
    p.add_argument("--scenario", choices=scenario_names(), required=True)
    p.add_argument("--observed-codes", default=None)
    p.add_argument("--out", type=Path, default=None)

    p = sub.add_parser("plan-grok")
    p.add_argument("--backend", choices=sorted(BACKENDS), required=True)
    p.add_argument("--grok", type=Path, required=True)
    p.add_argument("--out", type=Path, default=None)

    p = sub.add_parser("import-realcase")
    p.add_argument("--backend", choices=sorted(BACKENDS), default="powerdns")
    p.add_argument("--grok", type=Path, required=True)
    p.add_argument("--domain", default=None)
    p.add_argument("--out-dir", type=Path, default=None)
    p.add_argument("--repair-controlled", action="store_true")
    p.add_argument("--rotate-keys", action="store_true")

    p = sub.add_parser("execute-grok-controlled")
    p.add_argument("--backend", choices=sorted(BACKENDS), required=True)
    p.add_argument("--grok", type=Path, required=True)
    p.add_argument("--rotate-keys", action="store_true")
    p.add_argument("--out", type=Path, default=None)

    p = sub.add_parser("repair-controlled")
    p.add_argument("--backend", choices=sorted(BACKENDS), required=True)
    p.add_argument("--prefix", default="repair-controlled")
    p.add_argument("--rotate-keys", action="store_true")
    p.add_argument("--out", type=Path, default=None)

    p = sub.add_parser("iterate-controlled")
    p.add_argument("--backend", choices=sorted(BACKENDS), required=True)
    p.add_argument("--max-iterations", type=int, default=5)
    p.add_argument("--prefix", default="iterative-repair")
    p.add_argument("--rotate-keys", action="store_true")
    p.add_argument("--out", type=Path, default=None)

    p = sub.add_parser("deploy-controlled")
    p.add_argument("--backend", choices=sorted(BACKENDS), required=True)
    p.add_argument("--prefix", default="deploy-controlled")
    p.add_argument("--no-verify", action="store_true")
    p.add_argument("--out", type=Path, default=None)

    p = sub.add_parser("deploy-realcase")
    p.add_argument("--backend", choices=sorted(BACKENDS), required=True)
    p.add_argument("--domain", required=True)
    p.add_argument("--qname", action="append", default=None)
    p.add_argument("--live-grok", type=Path, default=None, help="existing DNSViz grok JSON; skips live capture")
    p.add_argument("--zone-file", type=Path, default=None, help="authoritative zone export used as the complete record source")
    p.add_argument("--axfr-server", default=None, help="authoritative server that permits AXFR")
    p.add_argument("--axfr-port", type=int, default=53)
    p.add_argument("--allow-partial-records", action="store_true", help="allow an incomplete recursive-DNS sample for lab-only use")
    p.add_argument("--prefix", default=None)
    p.add_argument("--out-dir", type=Path, default=None)
    p.add_argument("--no-verify", action="store_true")
    p.add_argument("--out", type=Path, default=None)

    p = sub.add_parser("execute")
    p.add_argument("--backend", choices=sorted(BACKENDS), required=True)
    p.add_argument("--scenario", choices=scenario_names(), required=True)
    p.add_argument("--observed-codes", default=None)
    p.add_argument("--out", type=Path, default=None)

    args = parser.parse_args()
    if args.cmd == "plan":
        plan = plan_scenario(args.backend, args.scenario, args.observed_codes)
    elif args.cmd == "plan-grok":
        import dnsviz_grok_adapter

        plan = dnsviz_grok_adapter.plan_from_grok(args.grok, args.backend)
    elif args.cmd == "import-realcase":
        import realcase_chain_importer

        result = realcase_chain_importer.import_realcase(
            args.grok,
            backend=args.backend,
            domain=args.domain,
            out_dir=args.out_dir,
            repair_controlled=args.repair_controlled,
            rotate_keys=args.rotate_keys,
        )
        print(json.dumps(asdict(result), ensure_ascii=False, indent=2))
        return
    elif args.cmd == "execute-grok-controlled":
        import controlled_zone_repair

        result = controlled_zone_repair.repair_lab_from_grok(args.backend, args.grok, rotate_keys=args.rotate_keys)
        text = json.dumps(asdict(result), ensure_ascii=False, indent=2)
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(text + "\n", encoding="utf-8")
        print(text)
        return
    elif args.cmd == "repair-controlled":
        import iterative_controlled_repair

        result = iterative_controlled_repair.iterative_repair(
            args.backend,
            prefix=args.prefix,
            rotate_keys=args.rotate_keys,
        )
        text = json.dumps(asdict(result), ensure_ascii=False, indent=2)
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(text + "\n", encoding="utf-8")
        print(text)
        if not result.converged:
            raise SystemExit(1)
        return
    elif args.cmd == "iterate-controlled":
        import iterative_controlled_repair

        result = iterative_controlled_repair.iterative_repair(
            args.backend,
            max_iterations=args.max_iterations,
            prefix=args.prefix,
            rotate_keys=args.rotate_keys,
        )
        text = json.dumps(asdict(result), ensure_ascii=False, indent=2)
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(text + "\n", encoding="utf-8")
        print(text)
        if not result.converged:
            raise SystemExit(1)
        return
    elif args.cmd == "deploy-controlled":
        import controlled_dnssec_deploy

        result = controlled_dnssec_deploy.deploy_controlled(args.backend, prefix=args.prefix, verify=not args.no_verify)
        text = json.dumps(asdict(result), ensure_ascii=False, indent=2)
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(text + "\n", encoding="utf-8")
        print(text)
        if not result.converged:
            raise SystemExit(1)
        return
    elif args.cmd == "deploy-realcase":
        import controlled_dnssec_deploy

        result = controlled_dnssec_deploy.deploy_realcase(
            args.backend,
            domain=args.domain,
            qnames=tuple(args.qname) if args.qname else None,
            prefix=args.prefix,
            out_dir=args.out_dir,
            verify=not args.no_verify,
            live_grok=args.live_grok,
            zone_file=args.zone_file,
            axfr_server=args.axfr_server,
            axfr_port=args.axfr_port,
            allow_partial_records=args.allow_partial_records,
        )
        text = json.dumps(asdict(result), ensure_ascii=False, indent=2)
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(text + "\n", encoding="utf-8")
        print(text)
        if result.deploy.converged is False:
            raise SystemExit(1)
        return
    else:
        plan = execute_scenario_repair(args.backend, args.scenario, args.observed_codes)

    if args.out:
        write_plan(plan, args.out)
    print(json.dumps(plan_as_dict(plan), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

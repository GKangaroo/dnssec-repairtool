#!/usr/bin/env python3
"""Adapter from DNSViz grok JSON to local repair-engine diagnosis context.

This is the missing DFixer-like entry point: it makes repair planning depend on
DNSViz analysis data instead of a pre-known demo scenario.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import dnssec_repair_engine as repair


@dataclass(frozen=True)
class ErrorFinding:
    code: str
    domain: str
    path: str
    description: str = ""
    servers: tuple[str, ...] = ()


@dataclass(frozen=True)
class DNSKEYRecord:
    id: str
    key_tag: int | None
    algorithm: int | None
    flags: int | None
    key_length: int | None
    status: str = ""


@dataclass(frozen=True)
class DSRecord:
    id: str
    key_tag: int | None
    algorithm: int | None
    digest_type: int | None
    status: str = ""


@dataclass(frozen=True)
class AuthServer:
    name: str
    addresses: tuple[str, ...]


@dataclass(frozen=True)
class GrokDiagnosis:
    backend: str
    zone: str
    parent_zone: str | None
    error_codes: tuple[str, ...]
    findings: tuple[ErrorFinding, ...]
    dnskeys: tuple[DNSKEYRecord, ...]
    ds_records: tuple[DSRecord, ...]
    auth_servers: tuple[AuthServer, ...]
    nsec_mode: str | None
    nsec3_params: tuple[str, ...] | None

    def to_context(self) -> repair.DiagnosisContext:
        return repair.DiagnosisContext(
            backend=self.backend,
            scenario="wild-grok",
            expected_codes=self.error_codes,
            observed_codes=self.error_codes,
            zone=self.zone,
            parent_zone=self.parent_zone or "",
        )


def load_grok(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _walk_errors(obj: Any, domain: str, path: str, out: list[ErrorFinding]) -> None:
    if isinstance(obj, dict):
        errors = obj.get("errors")
        if isinstance(errors, list):
            for err in errors:
                if not isinstance(err, dict) or not err.get("code"):
                    continue
                out.append(
                    ErrorFinding(
                        code=str(err["code"]),
                        domain=domain,
                        path=path or "/",
                        description=str(err.get("description", "")),
                        servers=tuple(str(item) for item in err.get("servers", ()) if item),
                    )
                )
        for key, value in obj.items():
            if key == "errors":
                continue
            next_path = f"{path}/{key}" if path else f"/{key}"
            _walk_errors(value, domain, next_path, out)
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            _walk_errors(value, domain, f"{path}[{index}]", out)


def find_error_findings(analysis: dict[str, Any]) -> tuple[ErrorFinding, ...]:
    findings: list[ErrorFinding] = []
    for domain, data in analysis.items():
        if not isinstance(data, dict):
            continue
        _walk_errors(data, domain, f"/{domain}", findings)
    return tuple(findings)


def identify_zone_name(analysis: dict[str, Any], findings: tuple[ErrorFinding, ...]) -> str:
    candidate_domains = {finding.domain for finding in findings}
    zone_candidates = [
        domain
        for domain, data in analysis.items()
        if isinstance(data, dict) and "zone" in data and (not candidate_domains or domain in candidate_domains)
    ]
    if not zone_candidates:
        zone_candidates = [domain for domain, data in analysis.items() if isinstance(data, dict) and "zone" in data]
    if not zone_candidates:
        raise ValueError("could not identify zone from DNSViz grok JSON")
    return sorted(zone_candidates, key=len, reverse=True)[0]


def identify_parent_zone(analysis: dict[str, Any], zone: str) -> str | None:
    candidates = [
        domain
        for domain, data in analysis.items()
        if domain != zone and len(domain) < len(zone) and zone.endswith(domain) and isinstance(data, dict) and "zone" in data
    ]
    if not candidates:
        return None
    return sorted(candidates, key=len, reverse=True)[0]


def collect_dnskeys(analysis: dict[str, Any], zone: str) -> tuple[DNSKEYRecord, ...]:
    records = []
    for item in analysis.get(zone, {}).get("dnskey", ()) or ():
        if not isinstance(item, dict):
            continue
        records.append(
            DNSKEYRecord(
                id=str(item.get("id", "")),
                key_tag=item.get("key_tag"),
                algorithm=item.get("algorithm"),
                flags=item.get("flags"),
                key_length=item.get("key_length"),
                status=str(item.get("status", "")),
            )
        )
    return tuple(records)


def collect_ds_records(analysis: dict[str, Any], zone: str) -> tuple[DSRecord, ...]:
    records = []
    for item in analysis.get(zone, {}).get("delegation", {}).get("ds", ()) or ():
        if not isinstance(item, dict):
            continue
        records.append(
            DSRecord(
                id=str(item.get("id", "")),
                key_tag=item.get("key_tag"),
                algorithm=item.get("algorithm"),
                digest_type=item.get("digest_type"),
                status=str(item.get("status", "")),
            )
        )
    return tuple(records)


def collect_auth_servers(analysis: dict[str, Any], zone: str) -> tuple[AuthServer, ...]:
    zone_data = analysis.get(zone, {}).get("zone", {})
    servers = zone_data.get("servers", {}) if isinstance(zone_data, dict) else {}
    out = []
    for name, value in servers.items():
        if not isinstance(value, dict):
            continue
        out.append(AuthServer(name=str(name), addresses=tuple(str(item) for item in value.get("auth", ()))))
    return tuple(out)


def identify_nsec_params(analysis: dict[str, Any], zone: str) -> tuple[str | None, tuple[str, ...] | None]:
    queries = analysis.get(zone, {}).get("queries", {})
    if not isinstance(queries, dict):
        return None, None
    for query_data in queries.values():
        if not isinstance(query_data, dict):
            continue
        for denial_key in ("nodata", "nxdomain"):
            for denial in query_data.get(denial_key, ()) or ():
                if not isinstance(denial, dict):
                    continue
                for proof in denial.get("proof", ()) or ():
                    if "nsec" in proof:
                        return "NSEC", None
                    nsec3 = proof.get("nsec3")
                    if nsec3:
                        first = nsec3[0]
                        rdata = first.get("rdata", []) if isinstance(first, dict) else []
                        if rdata:
                            return "NSEC3", tuple(str(rdata[0]).split()[:4])
                        return "NSEC3", None
    return None, None


def ordered_codes(findings: tuple[ErrorFinding, ...]) -> tuple[str, ...]:
    seen = set()
    codes = []
    for finding in findings:
        if finding.code not in seen:
            seen.add(finding.code)
            codes.append(finding.code)
    return tuple(codes)


def diagnose_grok(path: Path, backend: str) -> GrokDiagnosis:
    backend = repair.normalize_backend(backend)
    analysis = load_grok(path)
    findings = find_error_findings(analysis)
    zone = identify_zone_name(analysis, findings)
    parent_zone = identify_parent_zone(analysis, zone)
    nsec_mode, nsec3_params = identify_nsec_params(analysis, zone)
    return GrokDiagnosis(
        backend=backend,
        zone=zone,
        parent_zone=parent_zone,
        error_codes=ordered_codes(findings),
        findings=findings,
        dnskeys=collect_dnskeys(analysis, zone),
        ds_records=collect_ds_records(analysis, zone),
        auth_servers=collect_auth_servers(analysis, zone),
        nsec_mode=nsec_mode,
        nsec3_params=nsec3_params,
    )


def plan_from_grok(path: Path, backend: str) -> repair.RepairPlan:
    diagnosis = diagnose_grok(path, backend)
    return repair.build_plan(diagnosis.to_context())


def topological_plan_from_grok(path: Path, backend: str) -> repair.RepairPlan:
    diagnosis = diagnose_grok(path, backend)
    return repair.build_topological_plan(diagnosis.to_context())


def diagnosis_as_dict(diagnosis: GrokDiagnosis) -> dict[str, Any]:
    return asdict(diagnosis)


def main() -> None:
    parser = argparse.ArgumentParser(description="Adapt DNSViz grok JSON into local DFixer-style diagnosis.")
    parser.add_argument("grok", type=Path)
    parser.add_argument("--backend", choices=sorted(repair.BACKENDS), default="bind9")
    parser.add_argument("--plan", action="store_true", help="print repair plan instead of raw diagnosis")
    parser.add_argument("--topological", action="store_true", help="when printing a plan, include only the top-priority repair")
    args = parser.parse_args()

    if args.plan:
        plan = topological_plan_from_grok(args.grok, args.backend) if args.topological else plan_from_grok(args.grok, args.backend)
        print(json.dumps(repair.plan_as_dict(plan), ensure_ascii=False, indent=2))
        return
    diagnosis = diagnose_grok(args.grok, args.backend)
    print(json.dumps(diagnosis_as_dict(diagnosis), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

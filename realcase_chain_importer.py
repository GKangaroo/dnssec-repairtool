#!/usr/bin/env python3
"""Import a real-domain DNSSEC chain capture into a local repair package.

The importer is intentionally offline-first. Public recursive/DoH access is not
reliable in every devbox, so the stable input is DNSViz grok JSON or a compatible
capture. The output is a reproducible package: normalized before records, a
local-lab clone view, repair plan, and optionally repaired lab records.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
from dataclasses import asdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import dnsviz_grok_adapter
import dnssec_repair_engine as repair


DNSSEC_TYPES = {"DNSKEY", "DS", "RRSIG", "NSEC", "NSEC3", "CDS", "CDNSKEY"}


@dataclass(frozen=True)
class ResourceRecord:
    owner: str
    ttl: int | None
    rrtype: str
    rdata: str
    source: str = ""
    status: str = ""

    def to_zone_line(self) -> str:
        ttl = f"{self.ttl} " if self.ttl is not None else ""
        return f"{self.owner} {ttl}IN {self.rrtype} {self.rdata}".strip()


@dataclass(frozen=True)
class RealcaseImportResult:
    domain: str
    zone: str
    parent_zone: str
    backend: str
    grok: str
    out_dir: str
    before_records: tuple[ResourceRecord, ...]
    lab_clone_records: tuple[ResourceRecord, ...]
    repaired_records: tuple[ResourceRecord, ...]
    plan: dict[str, Any]
    actions: tuple[str, ...]
    files: dict[str, str]
    notes: tuple[str, ...]


def _absolute_name(value: str) -> str:
    if value == ".":
        return value
    return value if value.endswith(".") else value + "."


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _dns_time(value: str) -> str:
    # DNSViz grok commonly uses "2026-07-22 05:48:27 UTC"; zone files need
    # YYYYMMDDHHMMSS. If it already looks like DNS time, keep it.
    text = str(value).strip()
    if re.fullmatch(r"\d{14}", text):
        return text
    match = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?: UTC)?", text)
    if match:
        return "".join(match.groups())
    return text


def _normalise_rdata(rrtype: str, value: Any) -> str:
    parts = str(value).split()
    if rrtype in {"DNSKEY", "CDNSKEY"} and len(parts) >= 4:
        return " ".join([*parts[:3], "".join(parts[3:])])
    if rrtype in {"DS", "CDS"} and len(parts) >= 4:
        return " ".join([*parts[:3], "".join(parts[3:])])
    return " ".join(parts)


def _normalise_digest(value: Any) -> str:
    text = "".join(str(value).split())
    if re.fullmatch(r"[0-9A-Fa-f]+", text):
        return text.lower()
    try:
        return base64.b64decode(text, validate=True).hex()
    except Exception:
        return text


def _rrsig_owner_rdata(covered_rrtype: str, item: dict[str, Any], sig: dict[str, Any]) -> tuple[str, str] | None:
    signer = sig.get("signer")
    algorithm = sig.get("algorithm")
    labels = sig.get("labels")
    original_ttl = sig.get("original_ttl")
    expiration = sig.get("expiration")
    inception = sig.get("inception")
    key_tag = sig.get("key_tag")
    signature = sig.get("signature")
    if None in {signer, algorithm, labels, original_ttl, expiration, inception, key_tag, signature}:
        return None
    rdata = " ".join(
        [
            covered_rrtype,
            str(algorithm),
            str(labels),
            str(original_ttl),
            _dns_time(str(expiration)),
            _dns_time(str(inception)),
            str(key_tag),
            _absolute_name(str(signer)),
            str(signature).replace(" ", ""),
        ]
    )
    return _absolute_name(str(item.get("name", ""))), rdata


def _records_from_rrset(item: dict[str, Any], source: str) -> list[ResourceRecord]:
    name = item.get("name")
    rrtype = str(item.get("type", "")).upper()
    rdata_values = item.get("rdata", ())
    if not name or not rrtype or not isinstance(rdata_values, list):
        return []

    out: list[ResourceRecord] = []
    owner = _absolute_name(str(name))
    ttl = _as_int(item.get("ttl"))
    status = str(item.get("status", ""))
    for rdata in rdata_values:
        out.append(ResourceRecord(owner, ttl, rrtype, _normalise_rdata(rrtype, rdata), source, status))

    for sig in item.get("rrsig", ()) or ():
        if not isinstance(sig, dict):
            continue
        rendered = _rrsig_owner_rdata(rrtype, item, sig)
        if rendered is None:
            continue
        sig_owner, sig_rdata = rendered
        out.append(ResourceRecord(sig_owner, _as_int(sig.get("ttl", ttl)), "RRSIG", sig_rdata, source, str(sig.get("status", ""))))
    return out


def _walk_query_records(obj: Any, source: str, out: list[ResourceRecord]) -> None:
    if isinstance(obj, dict):
        if {"name", "type", "rdata"}.issubset(obj):
            out.extend(_records_from_rrset(obj, source))
        for key, value in obj.items():
            next_source = f"{source}/{key}" if source else str(key)
            _walk_query_records(value, next_source, out)
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            _walk_query_records(value, f"{source}[{index}]", out)


def extract_records_from_grok(grok: Path) -> tuple[ResourceRecord, ...]:
    analysis = dnsviz_grok_adapter.load_grok(grok)
    records: list[ResourceRecord] = []
    for domain, data in analysis.items():
        if not isinstance(data, dict):
            continue
        _walk_query_records(data.get("queries", {}), f"/{domain}/queries", records)

        for key in data.get("dnskey", ()) or ():
            if not isinstance(key, dict) or not key.get("key"):
                continue
            rdata = f"{key.get('flags')} {key.get('protocol', 3)} {key.get('algorithm')} {str(key.get('key')).replace(' ', '')}"
            records.append(
                ResourceRecord(
                    _absolute_name(str(domain)),
                    _as_int(key.get("ttl")),
                    "DNSKEY",
                    rdata,
                    f"/{domain}/dnskey",
                    str(key.get("status", "")),
                )
            )

        delegation = data.get("delegation", {})
        ds_records = delegation.get("ds", ()) if isinstance(delegation, dict) else ()
        for ds in ds_records or ():
            if not isinstance(ds, dict) or not ds.get("digest"):
                continue
            rdata = f"{ds.get('key_tag')} {ds.get('algorithm')} {ds.get('digest_type')} {_normalise_digest(ds.get('digest'))}"
            records.append(
                ResourceRecord(
                    _absolute_name(str(domain)),
                    _as_int(ds.get("ttl")),
                    "DS",
                    rdata,
                    f"/{domain}/delegation/ds",
                    str(ds.get("status", "")),
                )
            )

    return _dedupe_records(records)


def _dedupe_records(records: list[ResourceRecord]) -> tuple[ResourceRecord, ...]:
    seen = set()
    out = []
    for record in records:
        key = (record.owner.lower(), record.ttl, record.rrtype, record.rdata)
        if key in seen:
            continue
        seen.add(key)
        out.append(record)
    return tuple(sorted(out, key=lambda rr: (rr.owner.lower(), rr.rrtype, rr.rdata)))


def clone_records_for_lab(records: tuple[ResourceRecord, ...], zone: str, parent_zone: str | None) -> tuple[ResourceRecord, ...]:
    zone = _absolute_name(zone)
    parent_zone = _absolute_name(parent_zone) if parent_zone else ""

    def rewrite_name(name: str) -> str:
        absolute = _absolute_name(name)
        if absolute == zone:
            return "example.com."
        if zone != "." and absolute.endswith("." + zone):
            return absolute[: -len(zone)] + "example.com."
        if parent_zone and absolute == parent_zone:
            return "com."
        if parent_zone and parent_zone != "." and absolute.endswith("." + parent_zone):
            return absolute[: -len(parent_zone)] + "com."
        return absolute

    cloned = []
    for record in records:
        rdata = record.rdata
        if record.rrtype == "RRSIG":
            parts = rdata.split()
            if len(parts) >= 8:
                parts[7] = rewrite_name(parts[7])
                rdata = " ".join(parts)
        elif record.rrtype in {"NS", "CNAME", "DNAME"}:
            rdata = rewrite_name(rdata.split()[0])
        cloned.append(ResourceRecord(rewrite_name(record.owner), record.ttl, record.rrtype, rdata, record.source, record.status))
    return _dedupe_records(cloned)


def _read_zone_records(path: Path, wanted_types: set[str] | None = None) -> tuple[ResourceRecord, ...]:
    if not path.exists():
        return ()
    records: list[ResourceRecord] = []
    pending = ""
    for raw in path.read_text(encoding="ascii").splitlines():
        line = raw.split(";", 1)[0].strip()
        if not line or line.startswith("$"):
            continue
        pending = f"{pending} {line}".strip() if pending else line
        if "(" in pending and ")" not in pending:
            continue
        flat = pending.replace("(", " ").replace(")", " ")
        pending = ""
        parts = flat.split()
        if len(parts) < 4:
            continue
        owner = parts[0]
        index = 1
        ttl = None
        if index < len(parts) and parts[index].isdigit():
            ttl = int(parts[index])
            index += 1
        if index < len(parts) and parts[index].upper() == "IN":
            index += 1
        if index >= len(parts):
            continue
        rrtype = parts[index].upper()
        if wanted_types and rrtype not in wanted_types:
            continue
        records.append(ResourceRecord(_absolute_name(owner), ttl, rrtype, " ".join(parts[index + 1 :]), str(path), ""))
    return _dedupe_records(records)


def collect_repaired_lab_records() -> tuple[ResourceRecord, ...]:
    import dnssec_lab

    paths = [
        dnssec_lab.LabContext().signed_zone_path("root"),
        dnssec_lab.LabContext().signed_zone_path("com"),
        dnssec_lab.LabContext().signed_zone_path("example"),
    ]
    records: list[ResourceRecord] = []
    for path in paths:
        records.extend(_read_zone_records(path, DNSSEC_TYPES | {"A", "NS", "SOA", "TXT"}))
    return _dedupe_records(records)


def _write_zone(path: Path, records: tuple[ResourceRecord, ...], title: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"; {title}", ""]
    lines.extend(record.to_zone_line() for record in records)
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="ascii")


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _default_out_dir(domain: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", domain.rstrip(".")).strip(".-") or "realcase"
    return Path("work") / "realcases" / safe


def import_realcase(
    grok: Path,
    *,
    backend: str,
    domain: str | None = None,
    out_dir: Path | None = None,
    repair_controlled: bool = False,
    rotate_keys: bool = False,
) -> RealcaseImportResult:
    backend = repair.normalize_backend(backend)
    diagnosis = dnsviz_grok_adapter.diagnose_grok(grok, backend)
    domain = _absolute_name(domain or diagnosis.zone)
    out_dir = out_dir or _default_out_dir(domain)
    before_records = extract_records_from_grok(grok)
    lab_clone_records = clone_records_for_lab(before_records, diagnosis.zone, diagnosis.parent_zone)
    plan = repair.build_plan(diagnosis.to_context())
    actions: tuple[str, ...] = ()
    repaired_records: tuple[ResourceRecord, ...] = ()

    if repair_controlled:
        import controlled_zone_repair

        result = controlled_zone_repair.repair_lab_from_grok(backend, grok, rotate_keys=rotate_keys)
        actions = result.actions
        repaired_records = collect_repaired_lab_records()

    files = {
        "before_records": str(out_dir / "before-records.zone"),
        "lab_clone_records": str(out_dir / "lab-clone-before.zone"),
        "repair_plan": str(out_dir / "repair-plan.json"),
        "summary": str(out_dir / "summary.json"),
    }
    if repaired_records:
        files["repaired_records"] = str(out_dir / "repaired-lab-records.zone")

    _write_zone(Path(files["before_records"]), before_records, f"Imported DNSSEC chain records for {domain}")
    _write_zone(Path(files["lab_clone_records"]), lab_clone_records, "Imported records rewritten to example.com./com. for local lab imitation")
    _write_json(Path(files["repair_plan"]), repair.plan_as_dict(plan))
    if repaired_records:
        _write_zone(Path(files["repaired_records"]), repaired_records, "Repaired DNSSEC/control records from current local lab")

    notes = (
        "offline grok import; no public DNS access was required",
        "lab-clone-before.zone is a normalized imitation view, not an automatic zone overwrite",
    )
    result = RealcaseImportResult(
        domain=domain,
        zone=diagnosis.zone,
        parent_zone=diagnosis.parent_zone or "",
        backend=backend,
        grok=str(grok),
        out_dir=str(out_dir),
        before_records=before_records,
        lab_clone_records=lab_clone_records,
        repaired_records=repaired_records,
        plan=repair.plan_as_dict(plan),
        actions=actions,
        files=files,
        notes=notes,
    )
    _write_json(Path(files["summary"]), asdict(result))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Import a real-domain DNSSEC chain capture and produce local repair records.")
    parser.add_argument("--grok", type=Path, required=True, help="DNSViz grok JSON or compatible capture")
    parser.add_argument("--backend", choices=sorted(repair.BACKENDS), default="powerdns")
    parser.add_argument("--domain", default=None, help="real domain label for output; defaults to detected zone")
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--repair-controlled", action="store_true", help="run the current local lab repair and export repaired records")
    parser.add_argument("--rotate-keys", action="store_true", help="rotate local lab child/parent keys before controlled repair")
    args = parser.parse_args()

    result = import_realcase(
        args.grok,
        backend=args.backend,
        domain=args.domain,
        out_dir=args.out_dir,
        repair_controlled=args.repair_controlled,
        rotate_keys=args.rotate_keys,
    )
    print(json.dumps(asdict(result), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

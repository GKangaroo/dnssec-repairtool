#!/usr/bin/env python3
"""Controlled-parent DNSSEC deployment for local BIND9/PowerDNS labs."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict
from dataclasses import dataclass
from pathlib import Path

import dnssec_lab
import dnssec_repair_engine as repair


@dataclass(frozen=True)
class ControlledDeployResult:
    backend: str
    zone: str
    parent_zone: str
    ds_record: str
    actions: tuple[str, ...]
    verify_grok: str | None
    final_codes: tuple[str, ...]
    converged: bool


@dataclass(frozen=True)
class ImportedRecord:
    owner: str
    ttl: int
    rrtype: str
    rdata: str
    source: str

    def to_zone_line(self) -> str:
        return f"{self.owner} {self.ttl} IN {self.rrtype} {self.rdata}"


@dataclass(frozen=True)
class RealcaseDeployResult:
    source_domain: str
    qnames: tuple[str, ...]
    imported_records: tuple[ImportedRecord, ...]
    deploy: ControlledDeployResult
    files: dict[str, str]


def write_trust_anchors() -> None:
    trusted = [dnssec_lab.root_key_record()]
    for ksk in dnssec_lab.key_files("com", ksk_only=True):
        trusted.append(ksk.read_text(encoding="ascii").strip())
    (dnssec_lab.OUT / "trusted.keys").write_text("\n".join(trusted) + "\n", encoding="ascii")


def build_unsigned_child_with_signed_parent_chain() -> None:
    dnssec_lab.ensure_keys()
    dnssec_lab.write_zone_files("good", include_example_ds=False, include_child_signals=True)
    write_trust_anchors()


def _absolute_name(value: str) -> str:
    if value == ".":
        return value
    return value if value.endswith(".") else value + "."


def _safe_label(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value.rstrip(".")).strip(".-") or "realcase"


def _default_qnames(domain: str) -> tuple[str, ...]:
    domain = _absolute_name(domain)
    www = "www." + domain
    return (domain, www)


def _rewrite_owner_to_lab(owner: str, source_domain: str, target_domain: str | None = None) -> str | None:
    owner = _absolute_name(owner)
    source_domain = _absolute_name(source_domain)
    target_domain = _absolute_name(target_domain or dnssec_lab.AUTH["example"]["zone"])
    if owner == source_domain:
        return target_domain
    suffix = "." + source_domain
    if owner.endswith(suffix):
        return owner[: -len(source_domain)] + target_domain
    return None


def _rewrite_rdata_names(rdata: str, source_domain: str, target_domain: str | None = None) -> str:
    source_domain = _absolute_name(source_domain)
    target_domain = _absolute_name(target_domain or dnssec_lab.AUTH["example"]["zone"])
    out = []
    for part in rdata.split():
        suffix = "." + source_domain
        if part == source_domain:
            out.append(target_domain)
        elif part.endswith(suffix):
            out.append(part[: -len(source_domain)] + target_domain)
        else:
            out.append(part)
    return " ".join(out)


def collect_public_business_records(domain: str, qnames: tuple[str, ...] | None = None) -> tuple[ImportedRecord, ...]:
    """Best-effort import of non-DNSSEC records from public DNS.

    DNSSEC deployment should start from normal business data, not from copied
    DNSKEY/DS/RRSIG records. The local lab then generates fresh DNSSEC material.
    """
    import dns.exception
    import dns.resolver

    domain = _absolute_name(domain)
    target_domain = dnssec_lab.AUTH["example"]["zone"]
    qnames = tuple(_absolute_name(item) for item in (qnames or _default_qnames(domain)))
    rrtypes_by_name = {domain: ("A", "AAAA", "MX", "TXT", "CNAME")}
    records: list[ImportedRecord] = []
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = 3
    resolver.timeout = 2

    for qname in qnames:
        rrtypes = rrtypes_by_name.get(qname, ("A", "AAAA", "TXT", "CNAME"))
        for rrtype in rrtypes:
            try:
                answer = resolver.resolve(qname, rrtype, raise_on_no_answer=False)
            except (dns.exception.DNSException, OSError):
                continue
            if not answer.rrset:
                continue
            owner = _rewrite_owner_to_lab(answer.rrset.name.to_text(), domain, target_domain)
            if owner is None:
                continue
            if owner == target_domain and rrtype == "CNAME":
                continue
            for rdata in answer:
                text = _rewrite_rdata_names(rdata.to_text(), domain, target_domain)
                records.append(ImportedRecord(owner, int(answer.rrset.ttl), rrtype, text, qname))

    seen = set()
    out: list[ImportedRecord] = []
    for record in records:
        key = (record.owner.lower(), record.rrtype, record.rdata)
        if key in seen:
            continue
        seen.add(key)
        out.append(record)
    return tuple(sorted(out, key=lambda item: (item.owner.lower(), item.rrtype, item.rdata)))


def write_unsigned_child_with_records(records: tuple[ImportedRecord, ...]) -> None:
    record_lines = "\n".join(record.to_zone_line() for record in records)
    child_zone = dnssec_lab.AUTH["example"]["zone"]
    child_ns = dnssec_lab.zone_ns("example")
    if not record_lines:
        record_lines = f'www.{child_zone} 300 IN A 192.0.2.10\n{child_zone} 300 IN TXT "dnssec lab example zone"'
    child_signals = "\n".join(
        (
            dnssec_lab.cds_from_ksk("example"),
            dnssec_lab.cdnskey_from_ksk("example"),
        )
    )
    dnssec_lab.LabContext().unsigned_zone_path("example").write_text(
        f"""$ORIGIN {child_zone}
$TTL 300
@ IN SOA {child_ns} hostmaster.{child_zone} (
    {dnssec_lab.SERIAL} 300 300 1200 300 )
@ IN NS {child_ns}
ns IN A {dnssec_lab.AUTH["example"]["ip"]}
{record_lines}
{child_signals}
""",
        encoding="ascii",
    )


def write_imported_records(path: Path, records: tuple[ImportedRecord, ...], domain: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"; Public business records imported from {domain}", ""]
    lines.extend(record.to_zone_line() for record in records)
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="ascii")


def publish_child_ds_to_parent() -> str:
    ds = dnssec_lab.ds_from_ksk("example")
    dnssec_lab.strip_ds_records(dnssec_lab.LabContext().unsigned_zone_path("com"), dnssec_lab.AUTH["example"]["zone"])
    with dnssec_lab.LabContext().unsigned_zone_path("com").open("a", encoding="ascii") as fh:
        fh.write(ds + "\n")
    return ds


def sign_deployed_chain() -> None:
    dnssec_lab.sign_zone("example", "good")
    dnssec_lab.sign_zone("com", "good")
    dnssec_lab.sign_zone("root", "good")


def start_backend(backend: str) -> None:
    backend = repair.normalize_backend(backend)
    if backend == "bind9":
        dnssec_lab.write_named_configs()
        dnssec_lab.start()
        return

    import powerdns_lab

    powerdns_lab.write_pdns_bind_configs()
    powerdns_lab.write_pdns_dnssec_metadata()
    resolver = dnssec_lab.CONF / "named-resolver.conf"
    resolver.write_text(dnssec_lab.named_conf_resolver(), encoding="ascii")
    powerdns_lab.run(["named-checkconf", str(resolver)])
    powerdns_lab.start()


def stop_backend(backend: str) -> None:
    backend = repair.normalize_backend(backend)
    if backend == "bind9":
        dnssec_lab.stop(quiet=True)
        return

    import powerdns_lab

    powerdns_lab.stop(quiet=True)


def setup_unsigned_lab(backend: str) -> tuple[str, ...]:
    backend = repair.normalize_backend(backend)
    if backend == "powerdns":
        import powerdns_lab

        powerdns_lab.stop(quiet=True)
    dnssec_lab.require_tools()
    dnssec_lab.reset_workdir()
    build_unsigned_child_with_signed_parent_chain()
    return (
        "initialize unsigned child zone with no parent DS and publish child CDS/CDNSKEY signals",
        "generate local KSK/ZSK material for child, parent and root",
    )


def verify_deployment(prefix: str) -> tuple[Path, tuple[str, ...]]:
    dnssec_lab.dnsviz(prefix)
    grok = dnssec_lab.OUT / f"{prefix}.grok.json"
    data = json.loads(grok.read_text(encoding="utf-8"))
    return grok, tuple(sorted(set(dnssec_lab.collect_codes(data))))


def deploy_controlled(backend: str, *, prefix: str = "deploy-controlled", verify: bool = True) -> ControlledDeployResult:
    backend = repair.normalize_backend(backend)
    dnssec_lab.reset_lab_zones()
    actions = list(setup_unsigned_lab(backend))
    ds = publish_child_ds_to_parent()
    actions.append("publish DS generated from child KSK into controlled parent zone")
    sign_deployed_chain()
    actions.append("sign child, parent and root zones")
    start_backend(backend)
    actions.append(f"start {backend} authoritative lab and validating resolver")

    verify_grok = None
    final_codes: tuple[str, ...] = ()
    if verify:
        grok, final_codes = verify_deployment(prefix)
        verify_grok = str(grok)
        actions.append("verify DNSSEC chain with DNSViz")

    return ControlledDeployResult(
        backend=backend,
        zone=dnssec_lab.AUTH["example"]["zone"],
        parent_zone=dnssec_lab.AUTH["com"]["zone"],
        ds_record=ds,
        actions=tuple(actions),
        verify_grok=verify_grok,
        final_codes=final_codes,
        converged=not final_codes,
    )


def deploy_realcase(
    backend: str,
    *,
    domain: str,
    qnames: tuple[str, ...] | None = None,
    prefix: str | None = None,
    out_dir: Path | None = None,
    verify: bool = True,
) -> RealcaseDeployResult:
    backend = repair.normalize_backend(backend)
    domain = _absolute_name(domain)
    dnssec_lab.configure_lab_zones(domain)
    qnames = tuple(_absolute_name(item) for item in (qnames or _default_qnames(domain)))
    prefix = prefix or f"deploy-realcase-{_safe_label(domain)}"
    out_dir = out_dir or (dnssec_lab.ROOT / "realcase-live" / _safe_label(domain) / "deploy")

    files: dict[str, str] = {}
    try:
        import realcase_chain_importer

        live_grok = dnssec_lab.dnsviz_live_domain(domain, qname=qnames[0], out_dir=out_dir / "live-chain")
        files["live_probe_grok"] = str(live_grok)
        live_import = realcase_chain_importer.import_realcase(
            live_grok,
            backend=backend,
            domain=domain,
            out_dir=out_dir / "live-chain" / "import",
        )
        files["live_chain_records"] = live_import.files["before_records"]
        files["live_chain_summary"] = live_import.files["summary"]
    except (Exception, SystemExit) as exc:
        files["live_chain_capture_error"] = str(exc)

    actions = list(setup_unsigned_lab(backend))
    imported = collect_public_business_records(domain, qnames)
    write_unsigned_child_with_records(imported)
    actions.append(
        f"import {len(imported)} public business record(s) and publish child CDS/CDNSKEY signals"
    )
    ds = publish_child_ds_to_parent()
    actions.append("publish DS generated from child KSK into controlled parent zone")
    sign_deployed_chain()
    actions.append("sign child, parent and root zones")
    start_backend(backend)
    actions.append(f"start {backend} authoritative lab and validating resolver")

    verify_grok = None
    final_codes: tuple[str, ...] = ()
    if verify:
        grok, final_codes = verify_deployment(prefix)
        verify_grok = str(grok)
        actions.append("verify DNSSEC chain with DNSViz")

    deploy = ControlledDeployResult(
        backend=backend,
        zone=dnssec_lab.AUTH["example"]["zone"],
        parent_zone=dnssec_lab.AUTH["com"]["zone"],
        ds_record=ds,
        actions=tuple(actions),
        verify_grok=verify_grok,
        final_codes=final_codes,
        converged=not final_codes,
    )
    files.update(
        {
            "imported_records": str(out_dir / "imported-business-records.zone"),
            "unsigned_child_zone": str(dnssec_lab.LabContext().unsigned_zone_path("example")),
        }
    )
    write_imported_records(Path(files["imported_records"]), imported, domain)
    import lab_config_exporter

    files["config_bundle"] = lab_config_exporter.export_config_bundle(
        backend,
        out_dir,
        source_domain=domain,
        purpose="deploy DNSSEC locally from public resolution-chain/business records",
    )
    return RealcaseDeployResult(
        source_domain=domain,
        qnames=qnames,
        imported_records=imported,
        deploy=deploy,
        files=files,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Deploy DNSSEC in the controlled local parent+child lab.")
    parser.add_argument("--backend", choices=sorted(repair.BACKENDS), required=True)
    parser.add_argument("--prefix", default="deploy-controlled")
    parser.add_argument("--domain", default=None, help="public source domain whose business records are imported before deployment")
    parser.add_argument("--qname", action="append", default=None, help="specific public qname to import; can be repeated")
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--no-verify", action="store_true")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()

    if args.domain:
        result = deploy_realcase(
            args.backend,
            domain=args.domain,
            qnames=tuple(args.qname) if args.qname else None,
            prefix=args.prefix,
            out_dir=args.out_dir,
            verify=not args.no_verify,
        )
        converged = result.deploy.converged
    else:
        result = deploy_controlled(args.backend, prefix=args.prefix, verify=not args.no_verify)
        converged = result.converged
    text = json.dumps(asdict(result), ensure_ascii=False, indent=2)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n", encoding="utf-8")
    print(text)
    if not converged:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

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
    converged: bool | None
    verification_scope: str


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
class RecordImportResult:
    records: tuple[ImportedRecord, ...]
    source: str
    complete: bool
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class RealcaseDeployResult:
    source_domain: str
    qnames: tuple[str, ...]
    imported_records: tuple[ImportedRecord, ...]
    record_source: str
    records_complete: bool
    record_warnings: tuple[str, ...]
    live_observed_codes: tuple[str, ...]
    public_changes_applied: bool
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
    rrtypes_by_name = {
        domain: (
            "A",
            "AAAA",
            "MX",
            "TXT",
            "CNAME",
            "CAA",
            "NAPTR",
            "SSHFP",
            "SVCB",
            "HTTPS",
            "URI",
        )
    }
    records: list[ImportedRecord] = []
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = 3
    resolver.timeout = 2

    for qname in qnames:
        rrtypes = rrtypes_by_name.get(
            qname,
            ("A", "AAAA", "MX", "TXT", "CNAME", "CAA", "SRV", "NAPTR", "SSHFP", "TLSA", "SVCB", "HTTPS", "URI"),
        )
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


def _records_from_zone(zone, domain: str, source: str) -> tuple[ImportedRecord, ...]:
    import dns.rdatatype

    domain = _absolute_name(domain)
    generated_types = {"RRSIG", "NSEC", "NSEC3", "NSEC3PARAM", "ZONEMD"}
    apex_control_types = {"SOA", "NS", "DNSKEY", "CDS", "CDNSKEY"}
    records: list[ImportedRecord] = []
    for owner_name, node in zone.nodes.items():
        owner = _absolute_name(owner_name.to_text())
        for rdataset in node.rdatasets:
            rrtype = dns.rdatatype.to_text(rdataset.rdtype)
            if rrtype in generated_types or (owner == domain and rrtype in apex_control_types):
                continue
            for rdata in rdataset:
                records.append(ImportedRecord(owner, int(rdataset.ttl), rrtype, rdata.to_text(), source))
    return tuple(sorted(records, key=lambda item: (item.owner.lower(), item.rrtype, item.rdata)))


def collect_zone_file_business_records(domain: str, zone_file: Path) -> tuple[ImportedRecord, ...]:
    import dns.zone

    domain = _absolute_name(domain)
    if not zone_file.is_file():
        raise SystemExit(f"zone file does not exist: {zone_file}")
    try:
        zone = dns.zone.from_file(str(zone_file), origin=domain, relativize=False, check_origin=False)
    except Exception as exc:
        raise SystemExit(f"could not parse authoritative zone file {zone_file}: {exc}") from exc
    return _records_from_zone(zone, domain, f"zone-file:{zone_file}")


def collect_axfr_business_records(domain: str, server: str, *, port: int = 53) -> tuple[ImportedRecord, ...]:
    import dns.query
    import dns.zone

    domain = _absolute_name(domain)
    try:
        transfer = dns.query.xfr(server, domain, port=port, lifetime=20, relativize=False)
        zone = dns.zone.from_xfr(transfer, relativize=False)
    except Exception as exc:
        raise SystemExit(f"AXFR failed for {domain} from {server}:{port}: {exc}") from exc
    return _records_from_zone(zone, domain, f"axfr:{server}:{port}")


def acquire_business_records(
    domain: str,
    *,
    qnames: tuple[str, ...] | None = None,
    zone_file: Path | None = None,
    axfr_server: str | None = None,
    axfr_port: int = 53,
    allow_partial_records: bool = False,
) -> RecordImportResult:
    if zone_file and axfr_server:
        raise SystemExit("--zone-file and --axfr-server are mutually exclusive")
    if zone_file:
        records = collect_zone_file_business_records(domain, zone_file)
        source = f"zone-file:{zone_file}"
        complete = True
        warnings: tuple[str, ...] = ()
    elif axfr_server:
        records = collect_axfr_business_records(domain, axfr_server, port=axfr_port)
        source = f"axfr:{axfr_server}:{axfr_port}"
        complete = True
        warnings = ()
    else:
        if not allow_partial_records:
            raise SystemExit(
                "refusing to build a deployment bundle from an incomplete recursive-DNS sample; "
                "provide --zone-file or --axfr-server, or explicitly use --allow-partial-records for a lab-only demo"
            )
        records = collect_public_business_records(domain, qnames)
        source = "recursive-dns-sample"
        complete = False
        warnings = (
            "recursive DNS cannot enumerate a complete zone; only explicitly queried names and RR types were imported",
        )
    if not records:
        if allow_partial_records:
            # Pure CNAME/empty domains may expose no business records over
            # recursive DNS; the lab zone writer already has a placeholder
            # fallback, so keep going for a lab-only demonstration.
            return RecordImportResult(records=(), source=source, complete=complete, warnings=warnings)
        raise SystemExit(f"no business records were imported from {source}")
    return RecordImportResult(records=records, source=source, complete=complete, warnings=warnings)


def _drop_cname_conflicts(records: tuple[ImportedRecord, ...], apex: str) -> tuple[ImportedRecord, ...]:
    """RFC 1034: a name may have a CNAME or other data, not both.

    Public captures sometimes contain CNAME plus A/TXT/MX at the same owner
    (non-authoritative views may expose both). BIND/pdns signers reject such
    zones, so keep only the CNAME for non-apex names and drop apex CNAMEs.
    """
    apex = _absolute_name(apex).lower()
    by_owner: dict[str, list[ImportedRecord]] = {}
    for record in records:
        by_owner.setdefault(record.owner.lower(), []).append(record)
    out: list[ImportedRecord] = []
    for owner, rrs in by_owner.items():
        cnames = [record for record in rrs if record.rrtype == "CNAME"]
        if owner == apex:
            out.extend(record for record in rrs if record.rrtype != "CNAME")
        elif cnames:
            out.extend(cnames)
        else:
            out.extend(rrs)
    return tuple(out)


def write_unsigned_child_with_records(records: tuple[ImportedRecord, ...]) -> None:
    records = _drop_cname_conflicts(records, dnssec_lab.AUTH["example"]["zone"])
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
        converged=not final_codes if verify else None,
        verification_scope="local-controlled",
    )


def deploy_realcase(
    backend: str,
    *,
    domain: str,
    qnames: tuple[str, ...] | None = None,
    prefix: str | None = None,
    out_dir: Path | None = None,
    verify: bool = True,
    live_grok: Path | None = None,
    zone_file: Path | None = None,
    axfr_server: str | None = None,
    axfr_port: int = 53,
    allow_partial_records: bool = False,
) -> RealcaseDeployResult:
    backend = repair.normalize_backend(backend)
    domain = _absolute_name(domain)
    dnssec_lab.configure_lab_zones(domain)
    qnames = tuple(_absolute_name(item) for item in (qnames or _default_qnames(domain)))
    prefix = prefix or f"deploy-realcase-{_safe_label(domain)}"
    out_dir = out_dir or (dnssec_lab.ROOT / "realcase-live" / _safe_label(domain) / "deploy")

    import dnsviz_grok_adapter
    import realcase_chain_importer

    if live_grok is None:
        live_grok = dnssec_lab.dnsviz_live_domain(domain, qname=qnames[0], out_dir=out_dir / "live-chain")
    elif not live_grok.is_file():
        raise SystemExit(f"DNSViz grok file does not exist: {live_grok}")
    diagnosis = dnsviz_grok_adapter.diagnose_grok(live_grok, backend)
    if _absolute_name(diagnosis.zone).lower() != domain.lower():
        raise SystemExit(
            f"DNSViz capture describes zone {diagnosis.zone}, not requested domain {domain}; "
            "use the diagnosed zone as --domain"
        )
    files: dict[str, str] = {"live_probe_grok": str(live_grok)}
    live_import = realcase_chain_importer.import_realcase(
        live_grok,
        backend=backend,
        domain=domain,
        out_dir=out_dir / "live-chain" / "import",
    )
    files["live_chain_records"] = live_import.files["before_records"]
    files["live_chain_summary"] = live_import.files["summary"]

    actions = list(setup_unsigned_lab(backend))
    record_import = acquire_business_records(
        domain,
        qnames=qnames,
        zone_file=zone_file,
        axfr_server=axfr_server,
        axfr_port=axfr_port,
        allow_partial_records=allow_partial_records,
    )
    imported = record_import.records
    write_unsigned_child_with_records(imported)
    actions.append(
        f"import {len(imported)} business record(s) from {record_import.source} and publish child CDS/CDNSKEY signals"
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
        converged=not final_codes if verify else None,
        verification_scope="local-controlled",
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
        record_source=record_import.source,
        records_complete=record_import.complete,
        record_warnings=record_import.warnings,
        live_observed_codes=diagnosis.error_codes,
        public_changes_applied=False,
        deploy=deploy,
        files=files,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Deploy DNSSEC in the controlled local parent+child lab.")
    parser.add_argument("--backend", choices=sorted(repair.BACKENDS), required=True)
    parser.add_argument("--prefix", default="deploy-controlled")
    parser.add_argument("--domain", default=None, help="public source domain whose business records are imported before deployment")
    parser.add_argument("--qname", action="append", default=None, help="specific public qname to import; can be repeated")
    parser.add_argument("--live-grok", type=Path, default=None, help="existing DNSViz grok JSON; skips live capture")
    parser.add_argument("--zone-file", type=Path, default=None, help="authoritative zone export used as the complete business-record source")
    parser.add_argument("--axfr-server", default=None, help="authoritative server that permits AXFR")
    parser.add_argument("--axfr-port", type=int, default=53)
    parser.add_argument("--allow-partial-records", action="store_true", help="allow an incomplete recursive-DNS sample for lab-only use")
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
            live_grok=args.live_grok,
            zone_file=args.zone_file,
            axfr_server=args.axfr_server,
            axfr_port=args.axfr_port,
            allow_partial_records=args.allow_partial_records,
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
    if converged is False:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

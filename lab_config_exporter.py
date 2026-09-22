#!/usr/bin/env python3
"""Export generated lab configuration into a readable handoff package."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import dnssec_lab
import dnssec_repair_engine as repair


def _zone_dir_label(internal_name: str) -> str:
    if internal_name == "root":
        return "root"
    meta = dnssec_lab.AUTH.get(internal_name)
    if not meta:
        return internal_name
    return meta["zone"].rstrip(".") or "root"


def _copy_matching(src_dir: Path, dst_dir: Path, patterns: tuple[str, ...]) -> list[str]:
    dst_dir.mkdir(parents=True, exist_ok=True)
    copied: list[str] = []
    for pattern in patterns:
        for src in sorted(src_dir.glob(pattern)):
            if not src.is_file():
                continue
            dst = dst_dir / src.name
            shutil.copy2(src, dst)
            copied.append(str(dst))
    return copied


def _export_name(internal_name: str) -> str:
    return _zone_dir_label(internal_name).replace("/", "_")


def _rewrite_zone_file_paths(text: str, bundle: Path) -> str:
    for internal_name, meta in dnssec_lab.AUTH.items():
        text = text.replace(
            str(dnssec_lab.ZONES / internal_name / f"{meta['file']}.signed"),
            str(bundle / "zones" / _zone_dir_label(internal_name) / f"{meta['file']}.signed"),
        )
    return text


def _rewrite_bind_config(text: str, bundle: Path) -> str:
    text = _rewrite_zone_file_paths(text, bundle)
    text = text.replace(str(dnssec_lab.CONF / "root.hints"), str(bundle / "named-conf" / "root.hints"))
    for internal_name in dnssec_lab.AUTH:
        export_name = _export_name(internal_name)
        text = text.replace(str(dnssec_lab.RUN / f"{internal_name}.pid"), str(bundle / "run" / f"{export_name}.pid"))
        text = text.replace(
            str(dnssec_lab.RUN / f"{internal_name}.session.key"),
            str(bundle / "run" / f"{export_name}.session.key"),
        )
    text = text.replace(str(dnssec_lab.RUN / "resolver.pid"), str(bundle / "run" / "resolver.pid"))
    text = text.replace(str(dnssec_lab.RUN / "resolver.session.key"), str(bundle / "run" / "resolver.session.key"))
    text = text.replace(str(dnssec_lab.WORK), str(bundle))
    return text


def _copy_bind_configs(dst_dir: Path, bundle: Path) -> list[str]:
    dst_dir.mkdir(parents=True, exist_ok=True)
    copied: list[str] = []
    root_hints = dnssec_lab.CONF / "root.hints"
    if root_hints.is_file():
        dst = dst_dir / "root.hints"
        shutil.copy2(root_hints, dst)
        copied.append(str(dst))
    for src in sorted(dnssec_lab.CONF.glob("named-*.conf")):
        if not src.is_file():
            continue
        dst_name = src.name
        for internal_name in dnssec_lab.AUTH:
            dst_name = dst_name.replace(f"named-{internal_name}", f"named-{_export_name(internal_name)}")
        dst = dst_dir / dst_name
        dst.write_text(_rewrite_bind_config(src.read_text(encoding="ascii"), bundle), encoding="ascii")
        copied.append(str(dst))
    return copied


def _powerdns_export_name(internal_name: str) -> str:
    return _export_name(internal_name)


def _rewrite_powerdns_config(text: str, bundle: Path) -> str:
    for internal_name, meta in dnssec_lab.AUTH.items():
        export_name = _powerdns_export_name(internal_name)
        text = text.replace(f"pdns-{internal_name}-zones.conf", f"pdns-{export_name}-zones.conf")
        text = text.replace(f"pdns-{internal_name}-dnssec.sqlite3", f"pdns-{export_name}-dnssec.sqlite3")
    text = _rewrite_zone_file_paths(text, bundle)
    text = text.replace(str(dnssec_lab.CONF), str(bundle / "powerdns-conf"))
    text = text.replace(str(dnssec_lab.WORK), str(bundle / "powerdns-dnssec-db"))
    return text


def _copy_powerdns_configs(dst_dir: Path, bundle: Path) -> list[str]:
    dst_dir.mkdir(parents=True, exist_ok=True)
    copied: list[str] = []
    for src in sorted(dnssec_lab.CONF.glob("pdns-*.conf")):
        if not src.is_file():
            continue
        dst_name = src.name
        for internal_name in dnssec_lab.AUTH:
            export_name = _powerdns_export_name(internal_name)
            dst_name = dst_name.replace(f"pdns-{internal_name}", f"pdns-{export_name}")
        dst = dst_dir / dst_name
        dst.write_text(_rewrite_powerdns_config(src.read_text(encoding="ascii"), bundle), encoding="ascii")
        copied.append(str(dst))
    return copied


def _copy_powerdns_dnssec_dbs(dst_dir: Path) -> list[str]:
    dst_dir.mkdir(parents=True, exist_ok=True)
    copied: list[str] = []
    for src in sorted(dnssec_lab.WORK.glob("pdns-*-dnssec.sqlite3")):
        if not src.is_file():
            continue
        dst_name = src.name
        for internal_name in dnssec_lab.AUTH:
            export_name = _powerdns_export_name(internal_name)
            dst_name = dst_name.replace(f"pdns-{internal_name}", f"pdns-{export_name}")
        dst = dst_dir / dst_name
        shutil.copy2(src, dst)
        copied.append(str(dst))
    return copied


def _copy_zone_tree(dst_dir: Path) -> list[str]:
    copied: list[str] = []
    for zone_dir in sorted(dnssec_lab.ZONES.iterdir()):
        if not zone_dir.is_dir():
            continue
        target = dst_dir / _zone_dir_label(zone_dir.name)
        target.mkdir(parents=True, exist_ok=True)
        for src in sorted(zone_dir.iterdir()):
            if not src.is_file():
                continue
            if not (src.name.startswith("db.") or src.name.endswith(".signed")):
                continue
            dst = target / src.name
            shutil.copy2(src, dst)
            copied.append(str(dst))
    return copied


def _productionize_child_zone(bundle: Path, public_ip: str) -> list[str]:
    """Rewrite child-zone NS glue to the public IP and re-sign in place.

    The lab signs zones that point at 127.10.0.x loopback addresses so the
    three-node lab can run on one host. For a production handoff the glue must
    match the parent-side delegation, so we substitute the real address and
    re-sign with the same keys (DS/CDS/CDNSKEY are unaffected by A records).
    """
    meta = dnssec_lab.AUTH["example"]
    zone = meta["zone"]
    label = _zone_dir_label("example")
    zone_dir = bundle / "zones" / label
    unsigned = zone_dir / meta["file"]
    signed = zone_dir / f"{meta['file']}.signed"
    if not unsigned.is_file():
        return []
    text = unsigned.read_text(encoding="ascii")
    lab_ip = meta["ip"]
    replaced = 0
    for ns_label in dnssec_lab.ns_labels("example"):
        old = f"{ns_label} IN A {lab_ip}"
        new = f"{ns_label} IN A {public_ip}"
        if old in text:
            text = text.replace(old, new)
            replaced += 1
    if not replaced:
        return []
    unsigned.write_text(text, encoding="ascii")
    subprocess.run(
        [
            "dnssec-signzone",
            "-S",
            "-K",
            str(dnssec_lab.KEYS / "example"),
            "-o",
            zone,
            "-f",
            str(signed),
            "-e",
            dnssec_lab.FUTURE_END,
            str(unsigned),
        ],
        check=True,
        capture_output=True,
        cwd=str(zone_dir),
    )
    return [f"child glue A records rewritten to {public_ip} and zone re-signed"]


def _productionize_named_conf(bundle: Path, public_ip: str) -> list[str]:
    """Make the child authoritative named.conf listen for the public service.

    Also rewrites the container-absolute bundle paths to be relative to the
    bundle root, so the handoff package is portable across hosts (run named
    from the bundle root, e.g. ``named -c named-conf/<zone>.conf``).
    """
    changed: list[str] = []
    child_export = _export_name("example")
    for conf in sorted((bundle / "named-conf").glob(f"named-{child_export}.conf")):
        text = conf.read_text(encoding="ascii")
        lab_ip = dnssec_lab.AUTH["example"]["ip"]
        if f"{{ {lab_ip}; }};" in text:
            text = text.replace(f"{{ {lab_ip}; }};", "{ any; };")
            changed.append(f"{conf.name}: listen-on {lab_ip} -> any")
        # 容器绝对路径 -> 相对 bundle 根（配合 directory "."，从包根启动 named）
        text = text.replace(f'directory "{bundle}";', 'directory ".";')
        text = text.replace(f"{bundle}/", "")
        conf.write_text(text, encoding="ascii")
    return changed


def _productionize_powerdns_conf(bundle: Path, public_ip: str) -> list[str]:
    changed: list[str] = []
    conf_dir = bundle / "powerdns-conf"
    if not conf_dir.is_dir():
        return changed
    lab_ip = dnssec_lab.AUTH["example"]["ip"]
    for conf in sorted(conf_dir.glob("pdns-*.conf")):
        text = conf.read_text(encoding="ascii")
        if f"local-address={lab_ip}" in text:
            text = text.replace(f"local-address={lab_ip}", "local-address=0.0.0.0")
            conf.write_text(text, encoding="ascii")
            changed.append(f"{conf.name}: local-address {lab_ip} -> 0.0.0.0")
    return changed


def export_config_bundle(
    backend: str,
    out_dir: Path,
    *,
    source_domain: str | None = None,
    purpose: str,
    public_ip: str | None = None,
) -> str:
    backend = repair.normalize_backend(backend)
    bundle = out_dir / f"{backend}-config"
    if bundle.exists():
        shutil.rmtree(bundle)
    bundle.mkdir(parents=True, exist_ok=True)

    copied: list[str] = []
    if backend == "bind9":
        copied.extend(_copy_bind_configs(bundle / "named-conf", bundle))
    else:
        copied.extend(_copy_powerdns_configs(bundle / "powerdns-conf", bundle))
        copied.extend(_copy_matching(dnssec_lab.CONF, bundle / "resolver-conf", ("named-resolver.conf",)))
        copied.extend(_copy_powerdns_dnssec_dbs(bundle / "powerdns-dnssec-db"))

    copied.extend(_copy_zone_tree(bundle / "zones"))
    copied.extend(_copy_matching(dnssec_lab.OUT, bundle / "dnsviz-output", ("*.grok.json", "*.repair-plan.json")))

    if public_ip:
        if backend == "bind9":
            _productionize_child_zone(bundle, public_ip)
            _productionize_named_conf(bundle, public_ip)
        else:
            _productionize_child_zone(bundle, public_ip)
            _productionize_powerdns_conf(bundle, public_ip)

    readme = bundle / "README.txt"
    backend_dir = "named-conf/" if backend == "bind9" else "powerdns-conf/"
    lines = [
        f"Purpose: {purpose}",
        f"Backend: {backend}",
        f"Source domain: {source_domain or 'N/A'}",
        "",
        "Start here:",
        f"1. {backend_dir} contains authoritative DNS configuration.",
        "2. zones/ contains the repaired unsigned and signed zone files.",
        "3. dnsviz-output/ contains the repair plan and before/after grok summaries.",
        "",
    ]
    if public_ip:
        lines += [
            "Production mode (--public-ip was given):",
            f"- Child zone NS glue A records were rewritten to {public_ip} and the zone was re-signed.",
            f"- {backend_dir} listens on {'any' if backend == 'bind9' else '0.0.0.0'} instead of the lab loopback.",
            "- Paths in the config are relative to this bundle root; run named from here:",
            "    mkdir -p run && named -c named-conf/<zone>.conf",
            "- Deploy: load zones/<domain>/<file>.signed plus the key material, run the backend on port 53,",
            "  make sure the parent-side delegation (NS + glue) matches these NS names, then wait for",
            "  the registry CDS scanner (e.g. fuyu) to publish the child DS from the CDS/CDNSKEY records.",
            "",
        ]
    else:
        lines += [
            "Notes:",
            "- This is a local lab bundle, not a direct registrar/API change.",
            "- For DNSSEC, the key user-visible parent-side change is the child DS record.",
            "- Large DNSViz probe captures and dsset helper files are intentionally omitted from this bundle.",
            "",
        ]
    readme.write_text("\n".join(lines), encoding="utf-8")
    return str(bundle)

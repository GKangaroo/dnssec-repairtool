#!/usr/bin/env python3
"""Export generated lab configuration into a readable handoff package."""

from __future__ import annotations

import shutil
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


def export_config_bundle(
    backend: str,
    out_dir: Path,
    *,
    source_domain: str | None = None,
    purpose: str,
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

    readme = bundle / "README.txt"
    backend_dir = "named-conf/" if backend == "bind9" else "powerdns-conf/"
    readme.write_text(
        "\n".join(
            [
                f"Purpose: {purpose}",
                f"Backend: {backend}",
                f"Source domain: {source_domain or 'N/A'}",
                "",
                "Start here:",
                f"1. {backend_dir} contains authoritative DNS configuration.",
                "2. zones/ contains the repaired unsigned and signed zone files.",
                "3. dnsviz-output/ contains the repair plan and before/after grok summaries.",
                "",
                "Notes:",
                "- This is a local lab bundle, not a direct registrar/API change.",
                "- For DNSSEC, the key user-visible parent-side change is the child DS record.",
                "- Large DNSViz probe captures and dsset helper files are intentionally omitted from this bundle.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return str(bundle)

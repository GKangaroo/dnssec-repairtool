#!/usr/bin/env python3
"""Zone-file backend adapters for controlled DNSSEC repair.

The adapters operate on the current zone backend instead of regenerating the
demo scenario from a template. This is the first production-shaped executor
boundary: preserve business records in unsigned zones, repair DNSSEC control
records, resign, and refresh the serving backend.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import dnssec_lab
import dnssec_repair_engine as repair


KEY_RESET_FAMILIES = {
    "dnskey_rrset_cleanup",
    "revoked_key_lifecycle",
    "unsupported_or_legacy_algorithm",
}

CHILD_SIGNAL_TYPES = {"CDS", "CDNSKEY"}


@dataclass(frozen=True)
class BackendRepairResult:
    backend: str
    actions: tuple[str, ...]


def _strip_owner_rrtypes(path: Path, owner_patterns: tuple[str, ...], rrtypes: set[str]) -> bool:
    lines = path.read_text(encoding="ascii").splitlines()
    kept = []
    changed = False
    rrtype_re = "|".join(re.escape(rrtype) for rrtype in sorted(rrtypes))
    owner_re = "|".join(owner_patterns)
    pattern = re.compile(rf"^\s*(?:{owner_re})\s+(?:\d+\s+)?(?:IN\s+)?(?:{rrtype_re})\b", re.IGNORECASE)
    for line in lines:
        if pattern.match(line):
            changed = True
            continue
        kept.append(line)
    if changed:
        path.write_text("\n".join(kept) + "\n", encoding="ascii")
    return changed


class ZoneFileBackendAdapter:
    backend = "zonefile"

    def __init__(self, *, rotate_keys: bool = False) -> None:
        self.rotate_keys = rotate_keys
        self.actions: list[str] = []

    @property
    def child_unsigned(self) -> Path:
        return dnssec_lab.LabContext().unsigned_zone_path("example")

    @property
    def parent_unsigned(self) -> Path:
        return dnssec_lab.LabContext().unsigned_zone_path("com")

    @property
    def root_unsigned(self) -> Path:
        return dnssec_lab.LabContext().unsigned_zone_path("root")

    def execute_plan(self, plan: repair.RepairPlan) -> BackendRepairResult:
        families = {instruction.family for instruction in plan.instructions}
        if self.rotate_keys or families & KEY_RESET_FAMILIES:
            self.rotate_child_and_parent_keys()

        if "cds_cdnskey_multi_signal" in families:
            self.remove_child_automation_signals()

        if families & {"ds_rrset_repair", "key_chain_repair", "revoked_key_lifecycle", "dnskey_rrset_cleanup", "unsupported_or_legacy_algorithm"}:
            self.repair_parent_ds()

        # Most DNSSEC data-plane failures are safely repaired by resigning the
        # current unsigned zones. This regenerates RRSIG/NSEC/NSEC3 while
        # preserving normal records already present in the backend.
        self.resign_all()
        return BackendRepairResult(backend=self.backend, actions=tuple(self.actions))

    def rotate_child_and_parent_keys(self) -> None:
        dnssec_lab.reset_keys("example")
        dnssec_lab.reset_keys("com")
        dnssec_lab.ensure_keys()
        self.actions.append("rotate child and parent DNSSEC keys")

    def remove_child_automation_signals(self) -> None:
        child_owner = re.escape(dnssec_lab.AUTH["example"]["zone"])
        changed = _strip_owner_rrtypes(self.child_unsigned, (r"@", child_owner), CHILD_SIGNAL_TYPES)
        if changed:
            self.actions.append("remove conflicting child CDS/CDNSKEY signals")

    def repair_parent_ds(self) -> None:
        dnssec_lab.strip_ds_records(self.parent_unsigned, dnssec_lab.AUTH["example"]["zone"])
        with self.parent_unsigned.open("a", encoding="ascii") as fh:
            fh.write(dnssec_lab.ds_from_ksk("example") + "\n")
        self.actions.append("replace parent DS with DS generated from current child KSK")

    def repair_root_ds(self) -> None:
        dnssec_lab.strip_ds_records(self.root_unsigned, dnssec_lab.AUTH["com"]["zone"])
        with self.root_unsigned.open("a", encoding="ascii") as fh:
            fh.write(dnssec_lab.ds_from_ksk("com") + "\n")
        self.actions.append("replace root DS with DS generated from current parent KSK")

    def resign_all(self) -> None:
        # If com. keys were rotated, root DS must be refreshed before signing.
        if any(action == "rotate child and parent DNSSEC keys" for action in self.actions):
            self.repair_root_ds()
        dnssec_lab.sign_zone("example", "good")
        dnssec_lab.sign_zone("com", "good")
        dnssec_lab.sign_zone("root", "good")
        self.actions.append("resign child, parent and root zones from current unsigned backend")

    def refresh(self) -> None:
        raise NotImplementedError


class Bind9ZoneFileAdapter(ZoneFileBackendAdapter):
    backend = "bind9"

    def refresh(self) -> None:
        dnssec_lab.restart()
        self.actions.append("restart BIND9 lab services")


class PowerDNSBindBackendAdapter(ZoneFileBackendAdapter):
    backend = "powerdns"

    def refresh(self) -> None:
        import powerdns_lab

        powerdns_lab.stop(quiet=True)
        powerdns_lab.write_pdns_bind_configs()
        powerdns_lab.write_pdns_dnssec_metadata()
        resolver = dnssec_lab.CONF / "named-resolver.conf"
        resolver.write_text(dnssec_lab.named_conf_resolver(), encoding="ascii")
        powerdns_lab.start()
        self.actions.append("refresh PowerDNS bind backend metadata and restart services")


def adapter_for_backend(backend: str, *, rotate_keys: bool = False) -> ZoneFileBackendAdapter:
    backend = repair.normalize_backend(backend)
    if backend == "bind9":
        return Bind9ZoneFileAdapter(rotate_keys=rotate_keys)
    return PowerDNSBindBackendAdapter(rotate_keys=rotate_keys)

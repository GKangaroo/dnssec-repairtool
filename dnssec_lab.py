#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from threading import Thread
from pathlib import Path

if __name__ == "__main__":
    sys.modules.setdefault("dnssec_lab", sys.modules[__name__])

from dnssec_scenarios import SCENARIOS as ERROR_SCENARIOS
from dnssec_scenarios import get as get_scenario
from dnssec_scenarios import names as scenario_names


ROOT = Path(__file__).resolve().parent
WORK = ROOT / "work"
KEYS = WORK / "keys"
ZONES = WORK / "zones"
CONF = WORK / "conf"
RUN = WORK / "run"
OUT = WORK / "out"
SHIM = WORK / "shim"
DNSVIZ_REPO_CANDIDATES = (ROOT / "dnsviz", ROOT.parent / "dnsviz")

AUTH = {
    "root": {"zone": ".", "ip": "127.10.0.1", "file": "db.root"},
    "com": {"zone": "com.", "ip": "127.10.0.2", "file": "db.com"},
    "example": {"zone": "example.com.", "ip": "127.10.0.3", "file": "db.example.com"},
}
RESOLVER_IP = "127.10.0.53"
DSYNC_PORT = 5359
SERIAL = "2026070601"
FUTURE_END = "20270706000000"
EXPIRED_START = "20250101000000"
EXPIRED_END = "20250102000000"
FUTURE_START = "20280101000000"
FUTURE_SIG_END = "20290101000000"
SCENARIOS = {"good", *ERROR_SCENARIOS}
FIXABLE_SCENARIOS = sorted(SCENARIOS - {"good"})


@dataclass(frozen=True)
class RealcaseRepairResult:
    source_domain: str
    backend: str
    live_grok: str
    observed_codes: tuple[str, ...]
    repair_plan: dict
    record_source: str
    records_complete: bool
    record_warnings: tuple[str, ...]
    imported_record_count: int
    actions: tuple[str, ...]
    local_verify_grok: str | None
    local_final_codes: tuple[str, ...]
    local_converged: bool | None
    verification_scope: str
    public_changes_applied: bool
    files: dict[str, str]


def absolute_name(value: str) -> str:
    if value == ".":
        return value
    return value if value.endswith(".") else value + "."


def parent_zone_for(zone: str) -> str:
    zone = absolute_name(zone)
    labels = zone.rstrip(".").split(".")
    if len(labels) < 2:
        raise ValueError(f"zone must have at least two labels: {zone}")
    return ".".join(labels[1:]) + "."


def configure_lab_zones(child_zone: str, parent_zone: str | None = None) -> None:
    """Configure the three-node lab to use real-looking child/parent names.

    The lab still runs three local authorities: root, parent, and child. The
    zone names, however, can be source-shaped, e.g. child=foo.bar.example.org.
    and parent=bar.example.org.
    """
    child_zone = absolute_name(child_zone)
    parent_zone = absolute_name(parent_zone) if parent_zone else parent_zone_for(child_zone)
    AUTH["com"]["zone"] = parent_zone
    AUTH["com"]["file"] = f"db.{parent_zone.rstrip('.')}"
    AUTH["example"]["zone"] = child_zone
    AUTH["example"]["file"] = f"db.{child_zone.rstrip('.')}"


def reset_lab_zones() -> None:
    configure_lab_zones("example.com.", "com.")


def zone_ns(zone_name: str) -> str:
    return "ns." + AUTH[zone_name]["zone"]


def lab_name(name: str) -> str:
    name = absolute_name(name)
    if name == "example.com.":
        return AUTH["example"]["zone"]
    if name.endswith(".example.com."):
        return name[: -len("example.com.")] + AUTH["example"]["zone"]
    if name == "com.":
        return AUTH["com"]["zone"]
    if name.endswith(".com."):
        return name[: -len("com.")] + AUTH["com"]["zone"]
    return name


def log(msg: str) -> None:
    print(f"[dnssec-lab] {msg}", flush=True)


def run(cmd, *, cwd=None, check=True, capture=False, sudo=False, env=None):
    if sudo and os.geteuid() != 0 and shutil.which("sudo") is not None:
        cmd = ["sudo", *cmd]
    kwargs = {
        "cwd": str(cwd) if cwd else None,
        "text": True,
        "env": env,
    }
    if capture:
        kwargs.update({"stdout": subprocess.PIPE, "stderr": subprocess.PIPE})
    else:
        kwargs.update({"stdout": None, "stderr": None})
    p = subprocess.run(cmd, **kwargs)
    if check and p.returncode != 0:
        if capture:
            print(p.stdout)
            print(p.stderr, file=sys.stderr)
        raise SystemExit(f"command failed ({p.returncode}): {' '.join(cmd)}")
    return p


def require_tools() -> None:
    missing = []
    for tool in ["named", "named-checkconf", "dnssec-keygen", "dnssec-signzone", "dnssec-dsfromkey", "dig", "dnsviz"]:
        if shutil.which(tool) is None:
            missing.append(tool)
    if missing:
        raise SystemExit("missing tools: " + ", ".join(missing))


def reset_workdir() -> None:
    stop(quiet=True)
    if WORK.exists():
        shutil.rmtree(WORK)
    for d in [KEYS, ZONES, CONF, RUN, OUT, SHIM]:
        d.mkdir(parents=True, exist_ok=True)
    for name in AUTH:
        (KEYS / name).mkdir(parents=True, exist_ok=True)
        (ZONES / name).mkdir(parents=True, exist_ok=True)


def key_files(name: str, ksk_only=False):
    files = sorted((KEYS / name).glob("K*.key"))
    if ksk_only:
        files = [p for p in files if re.search(r"\s(257|385)\s+3\s", p.read_text())]
    return files


def ensure_keys() -> None:
    for name, meta in AUTH.items():
        if key_files(name):
            continue
        keydir = KEYS / name
        zone = meta["zone"]
        log(f"generating KSK/ZSK for {zone}")
        run(["dnssec-keygen", "-K", str(keydir), "-a", "ECDSAP256SHA256", "-f", "KSK", "-n", "ZONE", zone], capture=True)
        run(["dnssec-keygen", "-K", str(keydir), "-a", "ECDSAP256SHA256", "-n", "ZONE", zone], capture=True)


def ensure_algorithm_keys(name: str, algorithm: str) -> None:
    keydir = KEYS / name
    existing = [p for p in key_files(name) if f"; alg = {algorithm}" in p.read_text(encoding="ascii")]
    if existing:
        return
    zone = AUTH[name]["zone"]
    run(["dnssec-keygen", "-K", str(keydir), "-a", algorithm, "-f", "KSK", "-n", "ZONE", zone], capture=True)
    run(["dnssec-keygen", "-K", str(keydir), "-a", algorithm, "-n", "ZONE", zone], capture=True)


def revoke_key(name: str, *, ksk: bool) -> None:
    candidates = key_files(name, ksk_only=ksk)
    if not ksk:
        candidates = [p for p in key_files(name) if " 256 3 " in p.read_text(encoding="ascii")]
    if not candidates:
        raise SystemExit(f"no {'KSK' if ksk else 'ZSK'} found for {name}")
    run(["dnssec-revoke", "-f", "-r", "-K", str(KEYS / name), candidates[0].name], cwd=KEYS / name, capture=True)


def reset_keys(name: str) -> None:
    shutil.rmtree(KEYS / name, ignore_errors=True)
    (KEYS / name).mkdir(parents=True, exist_ok=True)


def ds_from_ksk(name: str) -> str:
    ksks = key_files(name, ksk_only=True)
    if not ksks:
        raise SystemExit(f"no KSK found for {name}")
    return ds_from_key_file(name, ksks[0])


def ds_from_key_file(name: str, key_file: Path) -> str:
    p = run(["dnssec-dsfromkey", "-2", str(key_file)], capture=True)
    lines = [x.strip() for x in p.stdout.splitlines() if x.strip() and " IN DS " in x]
    if not lines:
        import dns.dnssec
        import dns.name
        import dns.rdata
        import dns.rdataclass
        import dns.rdatatype

        key_text = key_file.read_text(encoding="ascii").split()
        dnskey = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.DNSKEY,
            " ".join(key_text[key_text.index("DNSKEY") + 1 :]),
        )
        ds = dns.dnssec.make_ds(dns.name.from_text(AUTH[name]["zone"]), dnskey, "SHA256")
        return f"{AUTH[name]['zone']} IN DS {ds.to_text()}"
    return lines[0]


def ds_from_ksk_algorithm(name: str, algorithm: int) -> str:
    for ksk in key_files(name, ksk_only=True):
        parts = ksk.read_text(encoding="ascii").split()
        if "DNSKEY" not in parts:
            continue
        idx = parts.index("DNSKEY")
        if int(parts[idx + 3]) == algorithm:
            return ds_from_key_file(name, ksk)
    raise SystemExit(f"no KSK with DNSSEC algorithm {algorithm} found for {name}")


def ds_from_ksk_digest(name: str, digest: str) -> str:
    import dns.dnssec
    import dns.name
    import dns.rdata
    import dns.rdataclass
    import dns.rdatatype

    ksks = key_files(name, ksk_only=True)
    if not ksks:
        raise SystemExit(f"no KSK found for {name}")
    key_text = ksks[0].read_text(encoding="ascii").split()
    dnskey = dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.DNSKEY,
        " ".join(key_text[key_text.index("DNSKEY") + 1 :]),
    )
    ds = dns.dnssec.make_ds(
        dns.name.from_text(AUTH[name]["zone"]),
        dnskey,
        digest,
        policy=dns.dnssec.allow_all_policy,
    )
    return f"{AUTH[name]['zone']} IN DS {ds.to_text()}"


def cds_from_ksk(name: str) -> str:
    return ds_from_ksk(name).replace(" IN DS ", " IN CDS ", 1)


def corrupt_cds_from_ksk(name: str) -> str:
    parts = cds_from_ksk(name).split()
    digest = parts[-1]
    parts[-1] = digest[:-1] + ("0" if digest[-1].lower() != "0" else "1")
    return " ".join(parts)


def cdnskey_from_ksk(name: str) -> str:
    ksks = key_files(name, ksk_only=True)
    if not ksks:
        raise SystemExit(f"no KSK found for {name}")
    for line in ksks[0].read_text(encoding="ascii").splitlines():
        if " IN DNSKEY " in line and not line.lstrip().startswith(";"):
            return line.strip().replace(" IN DNSKEY ", " IN CDNSKEY ", 1)
    raise SystemExit(f"no DNSKEY record found in {ksks[0]}")


def dnskey_rdata_from_ksk(name: str) -> str:
    ksks = key_files(name, ksk_only=True)
    if not ksks:
        raise SystemExit(f"no KSK found for {name}")
    for line in ksks[0].read_text(encoding="ascii").splitlines():
        if " IN DNSKEY " in line and not line.lstrip().startswith(";"):
            parts = line.strip().split()
            idx = parts.index("DNSKEY")
            return " ".join(parts[idx + 1 :])
    raise SystemExit(f"no DNSKEY record found in {ksks[0]}")


def corrupt_cdnskey_from_ksk(name: str) -> str:
    import base64

    parts = cdnskey_from_ksk(name).split()
    key = bytearray(base64.b64decode(parts[-1]))
    if not key:
        raise SystemExit(f"could not corrupt empty CDNSKEY for {name}")
    key[-1] ^= 0x01
    parts[-1] = base64.b64encode(bytes(key)).decode("ascii")
    return " ".join(parts)


def corrupt_ds(ds: str) -> str:
    parts = ds.split()
    digest = parts[-1]
    parts[-1] = digest[:-1] + ("0" if digest[-1].lower() != "0" else "1")
    return " ".join(parts)


def ds_with_algorithm(ds: str, algorithm: int) -> str:
    parts = ds.split()
    idx = parts.index("DS")
    parts[idx + 2] = str(algorithm)
    return " ".join(parts)


def ds_with_digest_type(ds: str, digest_type: int) -> str:
    parts = ds.split()
    idx = parts.index("DS")
    parts[idx + 3] = str(digest_type)
    return " ".join(parts)


def encode_dns_name(name: str) -> bytes:
    name = name.rstrip(".")
    if not name:
        return b"\x00"
    out = bytearray()
    for label in name.split("."):
        raw = label.encode("ascii")
        if len(raw) > 63:
            raise SystemExit(f"DNS label too long: {label}")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def dsync_rdata(rrtype: int, scheme: int, port: int, target: str) -> str:
    wire = rrtype.to_bytes(2, "big") + scheme.to_bytes(1, "big") + port.to_bytes(2, "big") + encode_dns_name(target)
    return f"\\# {len(wire)} {wire.hex().upper()}"


def root_key_record() -> str:
    ksks = key_files("root", ksk_only=True)
    if not ksks:
        raise SystemExit("root KSK not found")
    return ksks[0].read_text().strip()


def root_trust_anchor() -> str:
    # Example DNSKEY line:
    # . IN DNSKEY 257 3 13 BASE64
    line = root_key_record()
    parts = line.split()
    idx = parts.index("DNSKEY")
    flags, proto, alg = parts[idx + 1 : idx + 4]
    key = "".join(parts[idx + 4 :])
    return f'trust-anchors {{ "." static-key {flags} {proto} {alg} "{key}"; }};'


def write_zone_files(scenario: str, *, include_example_ds: bool = True, include_dsync: bool = False, include_child_signals: bool = False) -> None:
    config = get_scenario(scenario)
    if config:
        include_example_ds = config.include_example_ds
    example_ds = ds_from_ksk("example")
    if config and config.corrupt_child_ds:
        example_ds = corrupt_ds(example_ds)

    com_ds = ds_from_ksk("com")

    child_zone = AUTH["example"]["zone"]
    parent_zone = AUTH["com"]["zone"]
    child_ns = zone_ns("example")
    parent_ns = zone_ns("com")

    example_ttl = config.example_ttl if config else 300
    extra_example_records = "\n".join(config.extra_example_records) if config else ""
    (ZONES / "example" / AUTH["example"]["file"]).write_text(
        f"""$ORIGIN {child_zone}
$TTL {example_ttl}
@ IN SOA {child_ns} hostmaster.{child_zone} (
    {SERIAL} {example_ttl} 300 1200 300 )
@ IN NS {child_ns}
ns IN A {AUTH["example"]["ip"]}
www IN A 192.0.2.10
@ IN TXT "dnssec lab example zone"
{extra_example_records}
{cds_from_ksk("example") if include_child_signals else ""}
{cdnskey_from_ksk("example") if include_child_signals else ""}
""",
        encoding="ascii",
    )

    dsync_line = (
        f"{child_zone.rstrip('.')}._dsync IN TYPE66 {dsync_rdata(59, 1, DSYNC_PORT, 'dsync-receiver.' + parent_zone)}"
        if include_dsync
        else ""
    )
    (ZONES / "com" / AUTH["com"]["file"]).write_text(
        f"""$ORIGIN {parent_zone}
$TTL 300
@ IN SOA {parent_ns} hostmaster.{parent_zone} (
    {SERIAL} 300 300 1200 300 )
@ IN NS {parent_ns}
ns IN A {AUTH["com"]["ip"]}
{child_zone} IN NS {child_ns}
{child_ns} IN A {AUTH["example"]["ip"]}
dsync-receiver IN A {AUTH["com"]["ip"]}
{dsync_line}
{example_ds if include_example_ds else ""}
""",
        encoding="ascii",
    )

    (ZONES / "root" / "db.root").write_text(
        f"""$ORIGIN .
$TTL 300
@ IN SOA ns.root. hostmaster.root. (
    {SERIAL} 300 300 1200 300 )
@ IN NS ns.root.
ns.root. IN A {AUTH["root"]["ip"]}
{parent_zone} IN NS {parent_ns}
{parent_ns} IN A {AUTH["com"]["ip"]}
{com_ds}
""",
        encoding="ascii",
    )


def sign_zone(name: str, scenario: str) -> None:
    meta = AUTH[name]
    zone = meta["zone"]
    zone_dir = ZONES / name
    unsigned = zone_dir / meta["file"]
    signed = zone_dir / f"{meta['file']}.signed"
    cmd = [
        "dnssec-signzone",
        "-S",
        "-K",
        str(KEYS / name),
        "-o",
        zone,
        "-f",
        str(signed),
    ]
    config = get_scenario(scenario)
    extra_args = config.sign_args(LabContext(), name) if config and config.sign_args else None
    if extra_args:
        cmd.extend(extra_args)
    else:
        cmd.extend(["-e", FUTURE_END])
    cmd.append(str(unsigned))
    run(cmd, cwd=zone_dir, capture=True)


def append_inconsistent_cds(path: Path, zone_name: str = "example") -> None:
    with path.open("a", encoding="ascii") as fh:
        fh.write(f"\n{corrupt_cds_from_ksk(zone_name)}\n")


def append_inconsistent_cdnskey(path: Path, zone_name: str = "example") -> None:
    with path.open("a", encoding="ascii") as fh:
        fh.write(f"\n{corrupt_cdnskey_from_ksk(zone_name)}\n")


def append_cds(path: Path, zone_name: str = "example") -> None:
    with path.open("a", encoding="ascii") as fh:
        fh.write(f"\n{cds_from_ksk(zone_name)}\n")


def append_cdnskey(path: Path, zone_name: str = "example") -> None:
    with path.open("a", encoding="ascii") as fh:
        fh.write(f"\n{cdnskey_from_ksk(zone_name)}\n")


def append_dnskey_at_owner(path: Path, owner: str, zone_name: str = "example") -> None:
    with path.open("a", encoding="ascii") as fh:
        fh.write(f"\n{owner} IN DNSKEY {dnskey_rdata_from_ksk(zone_name)}\n")


def append_ds_for_algorithm(path: Path, zone_name: str, algorithm: int) -> None:
    with path.open("a", encoding="ascii") as fh:
        fh.write(f"\n{ds_from_ksk_algorithm(zone_name, algorithm)}\n")


def append_ds_with_algorithm(path: Path, zone_name: str, algorithm: int) -> None:
    with path.open("a", encoding="ascii") as fh:
        fh.write(f"\n{ds_with_algorithm(ds_from_ksk(zone_name), algorithm)}\n")


def append_ds_with_digest(path: Path, zone_name: str, digest: str) -> None:
    with path.open("a", encoding="ascii") as fh:
        fh.write(f"\n{ds_from_ksk_digest(zone_name, digest)}\n")


def append_ds_with_digest_type(path: Path, zone_name: str, digest_type: int) -> None:
    with path.open("a", encoding="ascii") as fh:
        fh.write(f"\n{ds_with_digest_type(ds_from_ksk(zone_name), digest_type)}\n")


def strip_ds_records(path: Path, owner: str) -> None:
    owner_lhs = owner.rstrip(".") + "."
    lines = path.read_text(encoding="ascii").splitlines()
    kept = []
    for line in lines:
        data = line.split(";", 1)[0].strip()
        parts = data.split()
        if not parts or parts[0].startswith("$"):
            kept.append(line)
            continue

        rrtype_idx = 1
        while rrtype_idx < len(parts) and (parts[rrtype_idx].isdigit() or parts[rrtype_idx].upper() == "IN"):
            rrtype_idx += 1

        owner_matches = parts[0].rstrip(".") + "." == owner_lhs
        rrtype_matches = rrtype_idx < len(parts) and parts[rrtype_idx].upper() == "DS"
        if owner_matches and rrtype_matches:
            continue
        kept.append(line)
    path.write_text("\n".join(kept) + "\n", encoding="ascii")


def strip_dnskey_ksk(path: Path) -> None:
    lines = path.read_text(encoding="ascii").splitlines()
    kept = []
    skipping = False
    dnskey_ksk = re.compile(r"\bDNSKEY\s+257\s+3\b")
    for line in lines:
        starts = bool(dnskey_ksk.search(line))
        if starts:
            skipping = "(" in line and ")" not in line
            continue
        if skipping:
            if ")" in line:
                skipping = False
            continue
        kept.append(line)
    path.write_text("\n".join(kept) + "\n", encoding="ascii")


def strip_rrsig_a(path: Path) -> None:
    lines = path.read_text(encoding="ascii").splitlines()
    kept = []
    skipping = False
    rrsig_a = re.compile(r"\bRRSIG\s+A\b")
    for line in lines:
        starts = bool(rrsig_a.search(line))
        if starts:
            skipping = "(" in line and ")" not in line
            continue
        if skipping:
            if ")" in line:
                skipping = False
            continue
        kept.append(line)
    path.write_text("\n".join(kept) + "\n", encoding="ascii")


def strip_dnskey_rrsig_algorithm(path: Path, algorithm: int) -> None:
    strip_rrsig_type_algorithm(path, "DNSKEY", algorithm)


def strip_rrsig_type_algorithm(path: Path, covered_type: str, algorithm: int) -> None:
    lines = path.read_text(encoding="ascii").splitlines()
    kept = []
    skipping = False
    pattern = re.compile(rf"\bRRSIG\s+{re.escape(covered_type)}\s+{algorithm}\b")
    for line in lines:
        starts = bool(pattern.search(line))
        if starts:
            skipping = "(" in line and ")" not in line
            continue
        if skipping:
            if ")" in line:
                skipping = False
            continue
        kept.append(line)
    path.write_text("\n".join(kept) + "\n", encoding="ascii")


def strip_nsec_records(path: Path) -> None:
    lines = path.read_text(encoding="ascii").splitlines()
    kept = []
    skipping = False
    nsec = re.compile(r"\bNSEC\s+")
    for line in lines:
        starts = bool(nsec.search(line))
        if starts:
            skipping = "(" in line and ")" not in line
            continue
        if skipping:
            if ")" in line:
                skipping = False
            continue
        kept.append(line)
    path.write_text("\n".join(kept) + "\n", encoding="ascii")


def strip_nsec_owner(path: Path, owner: str) -> None:
    import dns.name
    import dns.rdataclass
    import dns.rdatatype
    import dns.zone

    origin = dns.name.from_text("example.com.")
    owner_name = dns.name.from_text(owner, origin=origin)
    zone = dns.zone.from_file(str(path), origin=origin, relativize=False)
    node = zone.get_node(owner_name)
    if node is None:
        raise SystemExit(f"could not find NSEC owner {owner} in {path}")
    try:
        node.delete_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC)
        node.delete_rdataset(dns.rdataclass.IN, dns.rdatatype.RRSIG, dns.rdatatype.NSEC)
    except KeyError:
        pass
    zone.to_file(str(path), sorted=True, relativize=False)


def strip_nsec3_owner(path: Path, owner: str) -> None:
    import dns.name
    import dns.rdataclass
    import dns.rdatatype
    import dns.zone

    origin = dns.name.from_text("example.com.")
    owner_name = dns.name.from_text(owner, origin=origin)
    zone = dns.zone.from_file(str(path), origin=origin, relativize=False)
    node = zone.get_node(owner_name)
    if node is None:
        raise SystemExit(f"could not find NSEC3 owner {owner} in {path}")
    try:
        node.delete_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC3)
        node.delete_rdataset(dns.rdataclass.IN, dns.rdatatype.RRSIG, dns.rdatatype.NSEC3)
    except KeyError:
        pass
    zone.to_file(str(path), sorted=True, relativize=False)


def mutate_nsec3_bitmap(
    path: Path,
    owner: str,
    *,
    add: tuple[str, ...] = (),
    remove: tuple[str, ...] = (),
    next_hash: str | None = None,
    zone_name: str = "example",
) -> None:
    import base64

    import dns.dnssec
    import dns.name
    import dns.rdata
    import dns.rdataclass
    import dns.rdataset
    import dns.rdatatype
    import dns.tokenizer
    import dns.zone
    import dns.rdtypes.ANY.NSEC3
    from cryptography.hazmat.primitives.asymmetric import ec

    origin = dns.name.from_text(AUTH[zone_name]["zone"])
    owner_name = dns.name.from_text(owner, origin=origin)
    zone = dns.zone.from_file(str(path), origin=origin, relativize=False)
    node = zone.get_node(owner_name)
    if node is None:
        raise SystemExit(f"could not find NSEC3 owner {owner} in {path}")

    rdataset = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC3)
    if rdataset is None:
        raise SystemExit(f"could not find NSEC3 RRset for {owner} in {path}")
    rdata = next(iter(rdataset))
    rdtypes = {dns.rdatatype.from_text(item) for item in rdata.to_text().split()[5:]}
    rdtypes.update(dns.rdatatype.from_text(item) for item in add)
    rdtypes.difference_update(dns.rdatatype.from_text(item) for item in remove)

    bitmap = dns.rdtypes.ANY.NSEC3.Bitmap.from_text(
        dns.tokenizer.Tokenizer(" ".join(dns.rdatatype.to_text(item) for item in sorted(rdtypes)))
    )
    kwargs = {"windows": bitmap}
    if next_hash is not None:
        kwargs["next"] = base64.b32hexdecode(next_hash.upper())
    new_rdata = rdata.replace(**kwargs)
    new_rdataset = dns.rdataset.from_rdata(rdataset.ttl, new_rdata)
    node.replace_rdataset(new_rdataset)

    try:
        node.delete_rdataset(dns.rdataclass.IN, dns.rdatatype.RRSIG, dns.rdatatype.NSEC3)
    except KeyError:
        pass

    zsk = next((p for p in key_files(zone_name) if " 256 3 13 " in p.read_text(encoding="ascii")), None)
    if zsk is None:
        raise SystemExit(f"could not find {AUTH[zone_name]['zone']} ECDSA P-256 ZSK")
    key_text = zsk.read_text(encoding="ascii").split()
    dnskey = dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.DNSKEY,
        " ".join(key_text[key_text.index("DNSKEY") + 1 :]),
    )
    private_text = zsk.with_suffix(".private").read_text(encoding="ascii").splitlines()
    private_b64 = next(line.split(": ", 1)[1] for line in private_text if line.startswith("PrivateKey:"))
    private_key = ec.derive_private_key(int.from_bytes(base64.b64decode(private_b64), "big"), ec.SECP256R1())
    rrsig = dns.dnssec.sign(
        (owner_name, new_rdataset),
        private_key,
        origin,
        dnskey,
        inception=dns_time(datetime.now(timezone.utc) - timedelta(hours=1)),
        expiration=FUTURE_END,
        verify=True,
    )
    rrsig_rdataset = node.find_rdataset(dns.rdataclass.IN, dns.rdatatype.RRSIG, covers=dns.rdatatype.NSEC3, create=True)
    rrsig_rdataset.add(rrsig, ttl=new_rdataset.ttl)
    node.replace_rdataset(rrsig_rdataset)

    zone.to_file(str(path), sorted=True, relativize=False)


def mutate_nsec_bitmap(
    path: Path,
    owner: str,
    *,
    add: tuple[str, ...] = (),
    remove: tuple[str, ...] = (),
    next_name: str | None = None,
    zone_name: str = "example",
) -> None:
    import base64

    import dns.name
    import dns.rdataclass
    import dns.rdataset
    import dns.rdatatype
    import dns.rdata
    import dns.dnssec
    import dns.tokenizer
    import dns.zone
    import dns.rdtypes.ANY.NSEC
    from cryptography.hazmat.primitives.asymmetric import ec

    origin = dns.name.from_text(AUTH[zone_name]["zone"])
    owner_name = dns.name.from_text(owner, origin=origin)
    zone = dns.zone.from_file(str(path), origin=origin, relativize=False)
    node = zone.get_node(owner_name)
    if node is None:
        raise SystemExit(f"could not find NSEC owner {owner} in {path}")

    rdataset = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC)
    if rdataset is None:
        raise SystemExit(f"could not find NSEC RRset for {owner} in {path}")
    rdata = next(iter(rdataset))
    rdtypes = {dns.rdatatype.from_text(item) for item in rdata.to_text().split()[1:]}
    rdtypes.update(dns.rdatatype.from_text(item) for item in add)
    rdtypes.difference_update(dns.rdatatype.from_text(item) for item in remove)

    nsec_rdata = dns.rdtypes.ANY.NSEC.NSEC(
        rdclass=dns.rdataclass.IN,
        rdtype=dns.rdatatype.NSEC,
        next=dns.name.from_text(next_name, origin=origin) if next_name else rdata.next,
        windows=dns.rdtypes.ANY.NSEC.Bitmap.from_text(
            dns.tokenizer.Tokenizer(" ".join(dns.rdatatype.to_text(item) for item in sorted(rdtypes)))
        ),
    )
    new_rdataset = dns.rdataset.from_rdata(rdataset.ttl, nsec_rdata)
    node.replace_rdataset(new_rdataset)

    try:
        node.delete_rdataset(dns.rdataclass.IN, dns.rdatatype.RRSIG, dns.rdatatype.NSEC)
    except KeyError:
        pass

    zsk = next((p for p in key_files(zone_name) if " 256 3 13 " in p.read_text(encoding="ascii")), None)
    if zsk is None:
        raise SystemExit(f"could not find {AUTH[zone_name]['zone']} ECDSA P-256 ZSK")
    key_text = zsk.read_text(encoding="ascii").split()
    dnskey = dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.DNSKEY,
        " ".join(key_text[key_text.index("DNSKEY") + 1 :]),
    )
    private_text = zsk.with_suffix(".private").read_text(encoding="ascii").splitlines()
    private_b64 = next(line.split(": ", 1)[1] for line in private_text if line.startswith("PrivateKey:"))
    private_key = ec.derive_private_key(int.from_bytes(base64.b64decode(private_b64), "big"), ec.SECP256R1())
    rrsig = dns.dnssec.sign(
        (owner_name, new_rdataset),
        private_key,
        origin,
        dnskey,
        inception=dns_time(datetime.now(timezone.utc) - timedelta(hours=1)),
        expiration=FUTURE_END,
        verify=True,
    )
    rrsig_rdataset = node.find_rdataset(dns.rdataclass.IN, dns.rdatatype.RRSIG, covers=dns.rdatatype.NSEC, create=True)
    rrsig_rdataset.add(rrsig, ttl=new_rdataset.ttl)
    node.replace_rdataset(rrsig_rdataset)

    zone.to_file(str(path), sorted=True, relativize=False)


def dns_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y%m%d%H%M%S")



def mutate_www_a_rrsig_signer(path: Path, signer: str = "com.") -> None:
    lines = path.read_text(encoding="ascii").splitlines()
    kept = []
    in_www = False
    in_rrsig_a = False
    rrsig_a = re.compile(r"\bRRSIG\s+A\b")
    signer_line = re.compile(r"(\s+\d{14}\s+\d{14}\s+\d+\s+)(\S+)(\s*)$")
    for line in lines:
        if line.startswith("www.example.com."):
            in_www = True
        elif line and not line.startswith((" ", "\t")):
            in_www = False

        if in_www and rrsig_a.search(line):
            in_rrsig_a = True
            kept.append(line)
            continue

        if in_rrsig_a:
            line = signer_line.sub(rf"\1{signer}\3", line)
            if ")" in line:
                in_rrsig_a = False
        kept.append(line)
    path.write_text("\n".join(kept) + "\n", encoding="ascii")


def mutate_www_a_rrsig_labels(path: Path, labels: int = 5) -> None:
    lines = path.read_text(encoding="ascii").splitlines()
    in_www = False
    rrsig_a = re.compile(r"\bRRSIG\s+A\b")
    for i, line in enumerate(lines):
        if line.startswith("www.example.com."):
            in_www = True
        elif line and not line.startswith((" ", "\t")):
            in_www = False
        if in_www and rrsig_a.search(line):
            lines[i] = re.sub(
                r"(\bRRSIG\s+A\s+\d+\s+)\d+(\s+\d+\s+\()",
                rf"\g<1>{labels}\2",
                line,
            )
            break
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def mutate_rrsig_labels_signed(path: Path, owner: str, rrtype_text: str, labels: int, zone_name: str = "example") -> None:
    import base64
    import struct

    import dns.dnssec
    import dns.name
    import dns.rdataclass
    import dns.rdatatype
    import dns.rdata
    import dns.zone
    import dns.rdtypes.ANY.RRSIG
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    origin = dns.name.from_text(AUTH[zone_name]["zone"])
    owner_name = dns.name.from_text(owner, origin=origin)
    rrtype = dns.rdatatype.from_text(rrtype_text)
    zone = dns.zone.from_file(str(path), origin=origin, relativize=False)
    node = zone.get_node(owner_name)
    if node is None:
        raise SystemExit(f"could not find owner {owner} in {path}")
    rdataset = node.get_rdataset(dns.rdataclass.IN, rrtype)
    if rdataset is None:
        raise SystemExit(f"could not find RRset {owner} {rrtype_text} in {path}")

    try:
        node.delete_rdataset(dns.rdataclass.IN, dns.rdatatype.RRSIG, rrtype)
    except KeyError:
        pass

    zsk = next((p for p in key_files(zone_name) if " 256 3 13 " in p.read_text(encoding="ascii")), None)
    if zsk is None:
        raise SystemExit(f"could not find {AUTH[zone_name]['zone']} ECDSA P-256 ZSK")
    key_text = zsk.read_text(encoding="ascii").split()
    dnskey = dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.DNSKEY,
        " ".join(key_text[key_text.index("DNSKEY") + 1 :]),
    )
    private_text = zsk.with_suffix(".private").read_text(encoding="ascii").splitlines()
    private_b64 = next(line.split(": ", 1)[1] for line in private_text if line.startswith("PrivateKey:"))
    private_key = ec.derive_private_key(int.from_bytes(base64.b64decode(private_b64), "big"), ec.SECP256R1())

    rrsig_template = dns.rdtypes.ANY.RRSIG.RRSIG(
        rdclass=dns.rdataclass.IN,
        rdtype=dns.rdatatype.RRSIG,
        type_covered=rrtype,
        algorithm=dnskey.algorithm,
        labels=labels,
        original_ttl=rdataset.ttl,
        expiration=dns.dnssec.to_timestamp(FUTURE_END),
        inception=dns.dnssec.to_timestamp(dns_time(datetime.now(timezone.utc) - timedelta(hours=1))),
        key_tag=dns.dnssec.key_id(dnskey),
        signer=origin,
        signature=b"",
    )
    data = b""
    data += rrsig_template.to_wire(origin=origin)[:18]
    data += rrsig_template.signer.to_digestable(origin)
    rrnamebuf = owner_name.to_digestable()
    rrfixed = struct.pack("!HHI", rdataset.rdtype, rdataset.rdclass, rrsig_template.original_ttl)
    for rdata in sorted(rdata.to_digestable(origin) for rdata in rdataset):
        data += rrnamebuf
        data += rrfixed
        data += struct.pack("!H", len(rdata))
        data += rdata
    der_signature = private_key.sign(data, ec.ECDSA(dns.dnssec._make_hash(rrsig_template.algorithm)))
    dsa_r, dsa_s = utils.decode_dss_signature(der_signature)
    signature = int.to_bytes(dsa_r, length=32, byteorder="big") + int.to_bytes(dsa_s, length=32, byteorder="big")
    rrsig = rrsig_template.replace(signature=signature)
    rrsig_rdataset = node.find_rdataset(dns.rdataclass.IN, dns.rdatatype.RRSIG, covers=rrtype, create=True)
    rrsig_rdataset.add(rrsig, ttl=rdataset.ttl)
    node.replace_rdataset(rrsig_rdataset)
    zone.to_file(str(path), sorted=True, relativize=False)


def mutate_www_a_signed_by_revoked_zsk(path: Path, zone_name: str = "example") -> None:
    import base64

    import dns.dnssec
    import dns.name
    import dns.rdataclass
    import dns.rdatatype
    import dns.rdata
    import dns.rdataset
    import dns.zone
    from cryptography.hazmat.primitives.asymmetric import ec

    origin = dns.name.from_text(AUTH[zone_name]["zone"])
    zone = dns.zone.from_file(str(path), origin=origin, relativize=False)
    apex = zone.get_node(origin)
    if apex is None:
        raise SystemExit(f"could not find zone apex in {path}")

    dnskey_rdataset = apex.get_rdataset(dns.rdataclass.IN, dns.rdatatype.DNSKEY)
    if dnskey_rdataset is None:
        raise SystemExit(f"could not find DNSKEY RRset in {path}")

    zsk = next((p for p in key_files(zone_name) if " 256 3 13 " in p.read_text(encoding="ascii")), None)
    if zsk is None:
        raise SystemExit(f"could not find {AUTH[zone_name]['zone']} ECDSA P-256 ZSK")

    revoked_dnskey = None
    new_dnskeys = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.DNSKEY)
    new_dnskeys.ttl = dnskey_rdataset.ttl
    for dnskey in dnskey_rdataset:
        if dnskey.flags == 256 and dnskey.algorithm == 13:
            revoked_dnskey = dnskey.replace(flags=384)
            new_dnskeys.add(revoked_dnskey, ttl=dnskey_rdataset.ttl)
        else:
            new_dnskeys.add(dnskey, ttl=dnskey_rdataset.ttl)
    if revoked_dnskey is None:
        raise SystemExit(f"could not find ZSK DNSKEY in {path}")
    apex.replace_rdataset(new_dnskeys)

    owner_name = dns.name.from_text("www.example.com.")
    node = zone.get_node(owner_name)
    if node is None:
        raise SystemExit(f"could not find www.example.com. in {path}")
    rdataset = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.A)
    if rdataset is None:
        raise SystemExit(f"could not find www.example.com. A in {path}")
    try:
        node.delete_rdataset(dns.rdataclass.IN, dns.rdatatype.RRSIG, dns.rdatatype.A)
    except KeyError:
        pass

    private_text = zsk.with_suffix(".private").read_text(encoding="ascii").splitlines()
    private_b64 = next(line.split(": ", 1)[1] for line in private_text if line.startswith("PrivateKey:"))
    private_key = ec.derive_private_key(int.from_bytes(base64.b64decode(private_b64), "big"), ec.SECP256R1())
    rrsig = dns.dnssec.sign(
        (owner_name, rdataset),
        private_key,
        origin,
        revoked_dnskey,
        inception=dns_time(datetime.now(timezone.utc) - timedelta(hours=1)),
        expiration=FUTURE_END,
        verify=True,
    )
    rrsig_rdataset = node.find_rdataset(dns.rdataclass.IN, dns.rdatatype.RRSIG, covers=dns.rdatatype.A, create=True)
    rrsig_rdataset.add(rrsig, ttl=rdataset.ttl)
    node.replace_rdataset(rrsig_rdataset)
    zone.to_file(str(path), sorted=True, relativize=False)


def mutate_www_a_rrset_ttl(path: Path, ttl: int = 600) -> None:
    lines = path.read_text(encoding="ascii").splitlines()
    for i, line in enumerate(lines):
        if line.startswith("www.example.com.") and re.search(r"\bIN\s+A\b", line):
            lines[i] = re.sub(r"^(\S+\s+)\d+(\s+IN\s+A\s+)", rf"\g<1>{ttl}\2", line)
            break
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def mutate_www_a_rrsig_record_ttl(path: Path, ttl: int = 600) -> None:
    lines = path.read_text(encoding="ascii").splitlines()
    in_www = False
    rrsig_a = re.compile(r"\bRRSIG\s+A\b")
    for i, line in enumerate(lines):
        if line.startswith("www.example.com."):
            in_www = True
        elif line and not line.startswith((" ", "\t")):
            in_www = False
        if in_www and rrsig_a.search(line):
            lines[i] = re.sub(r"^(\s*)\d+(\s+RRSIG\s+A\s+)", rf"\g<1>{ttl}\2", line)
            break
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def mutate_multiline_rr(path: Path, start_pattern: re.Pattern, mutator) -> None:
    lines = path.read_text(encoding="ascii").splitlines()
    out = []
    block = []
    in_block = False
    changed = False
    for line in lines:
        if not in_block and start_pattern.search(line):
            in_block = True
            block = [line]
            if ")" in line:
                out.extend(mutator(block))
                in_block = False
                changed = True
            continue
        if in_block:
            block.append(line)
            if ")" in line:
                out.extend(mutator(block))
                in_block = False
                changed = True
            continue
        out.append(line)
    if in_block:
        out.extend(block)
    if not changed:
        raise SystemExit(f"could not find record matching {start_pattern.pattern} in {path}")
    path.write_text("\n".join(out) + "\n", encoding="ascii")


def mutate_rrsig_signature(
    path: Path,
    rrtype: str = "A",
    owner: str = "www.example.com.",
    replacement: str = "AA==",
    algorithm: int | None = None,
) -> None:
    if algorithm is None:
        rrsig = re.compile(rf"\bRRSIG\s+{re.escape(rrtype)}\b")
    else:
        rrsig = re.compile(rf"\bRRSIG\s+{re.escape(rrtype)}\s+{algorithm}\b")
    lines = path.read_text(encoding="ascii").splitlines()
    out = []
    block = []
    in_block = False
    changed = False
    in_owner = False
    for line in lines:
        if not in_block:
            if line.startswith(owner):
                in_owner = True
            elif line and not line.startswith((" ", "\t")):
                in_owner = False
            if in_owner and rrsig.search(line):
                in_block = True
                block = [line]
                continue
            out.append(line)
            continue
        block.append(line)
        if ")" in line:
            out.extend(_replace_rrsig_signature_block(block, replacement))
            in_block = False
            changed = True
    if in_block:
        out.extend(block)
    if not changed:
        raise SystemExit(f"could not find RRSIG {rrtype} for {owner}")
    path.write_text("\n".join(out) + "\n", encoding="ascii")


def mutate_rrsig_algorithm(path: Path, rrtype: str, owner: str, new_algorithm: int) -> None:
    pattern = re.compile(rf"(\bRRSIG\s+{re.escape(rrtype)}\s+)\d+(\s+)")
    lines = path.read_text(encoding="ascii").splitlines()
    changed = False
    in_owner = False
    for i, line in enumerate(lines):
        if line.startswith(owner):
            in_owner = True
        elif line and not line.startswith((" ", "\t")):
            in_owner = False
        if in_owner and pattern.search(line):
            lines[i] = pattern.sub(rf"\g<1>{new_algorithm}\2", line, count=1)
            changed = True
            break
    if not changed:
        raise SystemExit(f"could not find RRSIG {rrtype} for {owner}")
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def sign_apex_rrset_with_key_flag(path: Path, rrtype_text: str, key_flag: int, zone_name: str = "example") -> None:
    import base64

    import dns.dnssec
    import dns.name
    import dns.rdata
    import dns.rdataclass
    import dns.rdatatype
    import dns.zone
    from cryptography.hazmat.primitives.asymmetric import ec

    origin = dns.name.from_text(AUTH[zone_name]["zone"])
    rrtype = dns.rdatatype.from_text(rrtype_text)
    zone = dns.zone.from_file(str(path), origin=origin, relativize=False)
    apex = zone.get_node(origin)
    if apex is None:
        raise SystemExit(f"could not find zone apex in {path}")
    rdataset = apex.get_rdataset(dns.rdataclass.IN, rrtype)
    if rdataset is None:
        raise SystemExit(f"could not find apex {rrtype_text} RRset in {path}")

    try:
        apex.delete_rdataset(dns.rdataclass.IN, dns.rdatatype.RRSIG, rrtype)
    except KeyError:
        pass

    key_file = next((p for p in key_files(zone_name) if f" {key_flag} 3 13 " in p.read_text(encoding="ascii")), None)
    if key_file is None:
        raise SystemExit(f"could not find {AUTH[zone_name]['zone']} ECDSA P-256 key with flag {key_flag}")
    key_text = key_file.read_text(encoding="ascii").split()
    dnskey = dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.DNSKEY,
        " ".join(key_text[key_text.index("DNSKEY") + 1 :]),
    )
    private_text = key_file.with_suffix(".private").read_text(encoding="ascii").splitlines()
    private_b64 = next(line.split(": ", 1)[1] for line in private_text if line.startswith("PrivateKey:"))
    private_key = ec.derive_private_key(int.from_bytes(base64.b64decode(private_b64), "big"), ec.SECP256R1())
    rrsig = dns.dnssec.sign(
        (origin, rdataset),
        private_key,
        origin,
        dnskey,
        inception=dns_time(datetime.now(timezone.utc) - timedelta(hours=1)),
        expiration=FUTURE_END,
        verify=True,
    )
    rrsig_rdataset = apex.find_rdataset(dns.rdataclass.IN, dns.rdatatype.RRSIG, covers=rrtype, create=True)
    rrsig_rdataset.add(rrsig, ttl=rdataset.ttl)
    apex.replace_rdataset(rrsig_rdataset)
    zone.to_file(str(path), sorted=True, relativize=False)


def sign_apex_rrset_with_zsk(path: Path, rrtype_text: str, zone_name: str = "example") -> None:
    sign_apex_rrset_with_key_flag(path, rrtype_text, 256, zone_name=zone_name)


def sign_apex_rrset_with_ksk(path: Path, rrtype_text: str, zone_name: str = "example") -> None:
    sign_apex_rrset_with_key_flag(path, rrtype_text, 257, zone_name=zone_name)


def replace_apex_rrset(path: Path, rrtype_text: str, record_texts: list[str], zone_name: str = "example") -> None:
    import dns.name
    import dns.rdata
    import dns.rdataclass
    import dns.rdataset
    import dns.rdatatype
    import dns.zone

    origin = dns.name.from_text(AUTH[zone_name]["zone"])
    rrtype = dns.rdatatype.from_text(rrtype_text)
    zone = dns.zone.from_file(str(path), origin=origin, relativize=False)
    apex = zone.get_node(origin)
    if apex is None:
        raise SystemExit(f"could not find zone apex in {path}")

    try:
        apex.delete_rdataset(dns.rdataclass.IN, rrtype)
    except KeyError:
        pass
    rdataset = dns.rdataset.Rdataset(dns.rdataclass.IN, rrtype)
    rdataset.ttl = 300
    for record_text in record_texts:
        parts = record_text.split()
        idx = parts.index(rrtype_text)
        rdata_text = " ".join(parts[idx + 1 :])
        rdataset.add(dns.rdata.from_text(dns.rdataclass.IN, rrtype, rdata_text), ttl=300)
    apex.replace_rdataset(rdataset)
    zone.to_file(str(path), sorted=True, relativize=False)


def _dnskey_rdata_text(block: list[str]) -> str:
    tokens: list[str] = []
    for line in block:
        clean = line.split(";", 1)[0].replace("(", " ").replace(")", " ")
        tokens.extend(clean.split())
    idx = tokens.index("DNSKEY")
    return " ".join(tokens[idx + 1 :])


def mutate_zsk_dnskey_algorithm_and_rrsig(
    path: Path,
    rrtype: str,
    owner: str,
    new_algorithm: int,
    zone_name: str = "example",
) -> None:
    import dns.dnssec
    import dns.rdata
    import dns.rdataclass
    import dns.rdatatype

    lines = path.read_text(encoding="ascii").splitlines()
    out: list[str] = []
    block: list[str] = []
    in_block = False
    changed_dnskey = False
    key_tag: int | None = None
    start_pattern = re.compile(r"\bDNSKEY\s+256\s+3\s+13\b")
    alg_pattern = re.compile(r"(\bDNSKEY\s+256\s+3\s+)13(\b)")

    for line in lines:
        if not in_block:
            if start_pattern.search(line):
                in_block = True
                block = [alg_pattern.sub(rf"\g<1>{new_algorithm}\2", line, count=1)]
                continue
            out.append(line)
            continue
        block.append(line)
        if ")" in line:
            rdata = dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.DNSKEY,
                _dnskey_rdata_text(block),
            )
            key_tag = dns.dnssec.key_id(rdata)
            block[-1] = re.sub(r"key id = \d+", f"key id = {key_tag}", block[-1])
            out.extend(block)
            in_block = False
            changed_dnskey = True
    if in_block:
        out.extend(block)
    if not changed_dnskey or key_tag is None:
        raise SystemExit(f"could not find example ZSK DNSKEY in {path}")

    rrsig_pattern = re.compile(rf"(\bRRSIG\s+{re.escape(rrtype)}\s+)\d+(\s+)")
    lines = out
    changed_rrsig = False
    in_owner = False
    in_rrsig = False
    for i, line in enumerate(lines):
        if not in_rrsig:
            if line.startswith(owner):
                in_owner = True
            elif line and not line.startswith((" ", "\t")):
                in_owner = False
            if in_owner and rrsig_pattern.search(line):
                lines[i] = rrsig_pattern.sub(rf"\g<1>{new_algorithm}\2", line, count=1)
                in_rrsig = True
            continue
        parts = line.split()
        if len(parts) >= 4:
            parts[2] = str(key_tag)
            lines[i] = re.sub(r"\S+", parts[0], line, count=1)
            lines[i] = " ".join(parts)
            changed_rrsig = True
            break
    if not changed_rrsig:
        raise SystemExit(f"could not find RRSIG {rrtype} for {owner}")
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def corrupt_rrsig_signature(path: Path, rrtype: str = "A", owner: str = "www.example.com.") -> None:
    rrsig = re.compile(rf"\bRRSIG\s+{re.escape(rrtype)}\b")
    lines = path.read_text(encoding="ascii").splitlines()
    out = []
    block = []
    in_block = False
    changed = False
    in_owner = False
    for line in lines:
        if not in_block:
            if line.startswith(owner):
                in_owner = True
            elif line and not line.startswith((" ", "\t")):
                in_owner = False
            if in_owner and rrsig.search(line):
                in_block = True
                block = [line]
                continue
            out.append(line)
            continue
        block.append(line)
        if ")" in line:
            out.extend(_corrupt_rrsig_signature_block(block))
            in_block = False
            changed = True
    if in_block:
        out.extend(block)
    if not changed:
        raise SystemExit(f"could not find RRSIG {rrtype} for {owner}")
    path.write_text("\n".join(out) + "\n", encoding="ascii")


def _corrupt_rrsig_signature_block(block: list[str]) -> list[str]:
    body_indices = [i for i, line in enumerate(block) if i > 0 and not re.search(r"\d{14}\s+\d{14}\s+\d+\s+\S+", line)]
    if not body_indices:
        return block
    idx = body_indices[-1]
    line = block[idx]
    m = re.search(r"([A-Za-z0-9+/])(?=[A-Za-z0-9+/=]*\s*\)?)", line)
    if not m:
        return block
    pos = m.start(1)
    replacement = "A" if line[pos] != "A" else "B"
    block[idx] = line[:pos] + replacement + line[pos + 1 :]
    return block


def _replace_rrsig_signature_block(block: list[str], replacement: str) -> list[str]:
    # Keep all RRSIG metadata intact and replace only the base64 signature body.
    start = block[0]
    prefix = start.rsplit("(", 1)[0] + "("
    return [prefix, f"                                        {replacement} )"]


def mutate_dnskey_flag(path: Path, old_flag: int, new_flag: int) -> None:
    lines = path.read_text(encoding="ascii").splitlines()
    changed = False
    pattern = re.compile(rf"(\bDNSKEY\s+){old_flag}(\s+3\s+13\b)")
    for i, line in enumerate(lines):
        if pattern.search(line):
            lines[i] = pattern.sub(rf"\g<1>{new_flag}\2", line)
            changed = True
            break
    if not changed:
        raise SystemExit(f"could not find DNSKEY flag {old_flag} in {path}")
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def mutate_dnskey_public_key(path: Path, flag: int, replacement_lines: list[str], algorithm: int = 13) -> None:
    pattern = re.compile(rf"\bDNSKEY\s+{flag}\s+3\s+{algorithm}\b")

    def replace(block: list[str]) -> list[str]:
        start = block[0]
        prefix = start.rsplit("(", 1)[0] + "("
        suffix = ""
        for line in block:
            if ")" in line:
                suffix = line.split(")", 1)[1]
                break
        return [prefix, *[f"                                        {line}" for line in replacement_lines], f"                                        ){suffix}"]

    mutate_multiline_rr(path, pattern, replace)


class LabContext:
    EXPIRED_START = EXPIRED_START
    EXPIRED_END = EXPIRED_END
    FUTURE_START = FUTURE_START
    FUTURE_SIG_END = FUTURE_SIG_END
    FUTURE_END = FUTURE_END

    def signed_zone_path(self, name: str) -> Path:
        meta = AUTH[name]
        return ZONES / name / f"{meta['file']}.signed"

    def unsigned_zone_path(self, name: str) -> Path:
        meta = AUTH[name]
        return ZONES / name / meta["file"]

    def dns_time(self, value: datetime) -> str:
        return dns_time(value)

    def ensure_keys(self) -> None:
        ensure_keys()

    def ensure_algorithm_keys(self, name: str, algorithm: str) -> None:
        ensure_algorithm_keys(name, algorithm)

    def append_inconsistent_cds(self, path: Path, zone_name: str = "example") -> None:
        append_inconsistent_cds(path, zone_name)

    def append_inconsistent_cdnskey(self, path: Path, zone_name: str = "example") -> None:
        append_inconsistent_cdnskey(path, zone_name)

    def append_cds(self, path: Path, zone_name: str = "example") -> None:
        append_cds(path, zone_name)

    def append_cdnskey(self, path: Path, zone_name: str = "example") -> None:
        append_cdnskey(path, zone_name)

    def cds_from_ksk(self, zone_name: str = "example") -> str:
        return cds_from_ksk(zone_name)

    def corrupt_cds_from_ksk(self, zone_name: str = "example") -> str:
        return corrupt_cds_from_ksk(zone_name)

    def cdnskey_from_ksk(self, zone_name: str = "example") -> str:
        return cdnskey_from_ksk(zone_name)

    def corrupt_cdnskey_from_ksk(self, zone_name: str = "example") -> str:
        return corrupt_cdnskey_from_ksk(zone_name)

    def append_dnskey_at_owner(self, path: Path, owner: str, zone_name: str = "example") -> None:
        append_dnskey_at_owner(path, owner, zone_name)

    def append_ds_for_algorithm(self, path: Path, zone_name: str, algorithm: int) -> None:
        append_ds_for_algorithm(path, zone_name, algorithm)

    def append_ds_with_algorithm(self, path: Path, zone_name: str, algorithm: int) -> None:
        append_ds_with_algorithm(path, zone_name, algorithm)

    def append_ds_with_digest(self, path: Path, zone_name: str, digest: str) -> None:
        append_ds_with_digest(path, zone_name, digest)

    def append_ds_with_digest_type(self, path: Path, zone_name: str, digest_type: int) -> None:
        append_ds_with_digest_type(path, zone_name, digest_type)

    def strip_ds_records(self, path: Path, owner: str) -> None:
        strip_ds_records(path, owner)

    def revoke_key(self, name: str, *, ksk: bool) -> None:
        revoke_key(name, ksk=ksk)

    def reset_keys(self, name: str) -> None:
        reset_keys(name)

    def strip_dnskey_ksk(self, path: Path) -> None:
        strip_dnskey_ksk(path)

    def strip_rrsig_a(self, path: Path) -> None:
        strip_rrsig_a(path)

    def strip_dnskey_rrsig_algorithm(self, path: Path, algorithm: int) -> None:
        strip_dnskey_rrsig_algorithm(path, algorithm)

    def strip_rrsig_type_algorithm(self, path: Path, covered_type: str, algorithm: int) -> None:
        strip_rrsig_type_algorithm(path, covered_type, algorithm)

    def strip_nsec_records(self, path: Path) -> None:
        strip_nsec_records(path)

    def strip_nsec_owner(self, path: Path, owner: str) -> None:
        strip_nsec_owner(path, owner)

    def strip_nsec3_owner(self, path: Path, owner: str) -> None:
        strip_nsec3_owner(path, owner)

    def mutate_nsec3_bitmap(
        self,
        path: Path,
        owner: str,
        *,
        add: tuple[str, ...] = (),
        remove: tuple[str, ...] = (),
        next_hash: str | None = None,
        zone_name: str = "example",
    ) -> None:
        mutate_nsec3_bitmap(path, owner, add=add, remove=remove, next_hash=next_hash, zone_name=zone_name)

    def mutate_nsec_bitmap(
        self,
        path: Path,
        owner: str,
        *,
        add: tuple[str, ...] = (),
        remove: tuple[str, ...] = (),
        next_name: str | None = None,
        zone_name: str = "example",
    ) -> None:
        mutate_nsec_bitmap(path, owner, add=add, remove=remove, next_name=next_name, zone_name=zone_name)

    def mutate_www_a_rrsig_signer(self, path: Path) -> None:
        mutate_www_a_rrsig_signer(path)

    def mutate_www_a_rrsig_labels(self, path: Path) -> None:
        mutate_www_a_rrsig_labels(path)

    def mutate_rrsig_labels_signed(self, path: Path, owner: str, rrtype_text: str, labels: int, zone_name: str = "example") -> None:
        mutate_rrsig_labels_signed(path, owner, rrtype_text, labels, zone_name=zone_name)

    def mutate_www_a_signed_by_revoked_zsk(self, path: Path, zone_name: str = "example") -> None:
        mutate_www_a_signed_by_revoked_zsk(path, zone_name)

    def mutate_www_a_rrset_ttl(self, path: Path, ttl: int = 600) -> None:
        mutate_www_a_rrset_ttl(path, ttl=ttl)

    def mutate_www_a_rrsig_record_ttl(self, path: Path) -> None:
        mutate_www_a_rrsig_record_ttl(path)

    def mutate_dnskey_public_key(self, path: Path, flag: int, replacement_lines: list[str], algorithm: int = 13) -> None:
        mutate_dnskey_public_key(path, flag, replacement_lines, algorithm=algorithm)

    def mutate_rrsig_signature(self, path: Path, replacement: str, algorithm: int | None = None) -> None:
        mutate_rrsig_signature(path, replacement=replacement, algorithm=algorithm)

    def mutate_rrsig_algorithm(self, path: Path, rrtype: str, owner: str, new_algorithm: int) -> None:
        mutate_rrsig_algorithm(path, rrtype, owner, new_algorithm)

    def sign_apex_rrset_with_zsk(self, path: Path, rrtype_text: str, zone_name: str = "example") -> None:
        sign_apex_rrset_with_zsk(path, rrtype_text, zone_name=zone_name)

    def sign_apex_rrset_with_ksk(self, path: Path, rrtype_text: str, zone_name: str = "example") -> None:
        sign_apex_rrset_with_ksk(path, rrtype_text, zone_name=zone_name)

    def replace_apex_rrset(self, path: Path, rrtype_text: str, record_texts: list[str], zone_name: str = "example") -> None:
        replace_apex_rrset(path, rrtype_text, record_texts, zone_name=zone_name)

    def mutate_zsk_dnskey_algorithm_and_rrsig(self, path: Path, rrtype: str, owner: str, new_algorithm: int, zone_name: str = "example") -> None:
        mutate_zsk_dnskey_algorithm_and_rrsig(path, rrtype, owner, new_algorithm, zone_name=zone_name)

    def corrupt_rrsig_signature(self, path: Path) -> None:
        corrupt_rrsig_signature(path)

    def sign_zone(self, name: str, scenario: str) -> None:
        sign_zone(name, scenario)


def build_zones(scenario: str) -> None:
    context = LabContext()
    config = get_scenario(scenario)
    ensure_keys()
    if config and config.before_write:
        config.before_write(context)
    write_zone_files(scenario)
    if config and config.before_sign:
        config.before_sign(context)
    # Sign bottom-up for child DS, then parent, then root. DS is computed from
    # DNSKEY, not from signatures, so the order is mostly for readability.
    for zone_name in ["example", "com", "root"]:
        sign_zone(zone_name, scenario)
        if config and config.after_sign_zone:
            config.after_sign_zone(context, zone_name)

    trusted = [root_key_record()]
    for ksk in key_files("com", ksk_only=True):
        trusted.append(ksk.read_text().strip())
    (OUT / "trusted.keys").write_text("\n".join(trusted) + "\n", encoding="ascii")
    if config and config.after_trusted_keys:
        config.after_trusted_keys(context)


def build_dsync_bootstrap_zones() -> None:
    ensure_keys()
    write_zone_files("good", include_example_ds=False, include_dsync=True, include_child_signals=True)
    sign_zone("example", "good")
    sign_zone("com", "good")
    sign_zone("root", "good")

    trusted = [root_key_record()]
    for ksk in key_files("com", ksk_only=True):
        trusted.append(ksk.read_text().strip())
    (OUT / "trusted.keys").write_text("\n".join(trusted) + "\n", encoding="ascii")


def cds_rrset_from_child(child: str) -> list[str]:
    import dns.message
    import dns.query
    import dns.rdatatype

    query = dns.message.make_query(child, dns.rdatatype.CDS, want_dnssec=True)
    response = dns.query.udp(query, AUTH["example"]["ip"], port=53, timeout=3)
    records = []
    for rrset in response.answer:
        if rrset.rdtype != dns.rdatatype.CDS:
            continue
        for rdata in rrset:
            records.append(
                f"{child} {rrset.ttl} IN DS {rdata.key_tag} {rdata.algorithm} {rdata.digest_type} {rdata.digest.hex().upper()}"
            )
    if not records:
        raise RuntimeError(f"no CDS records found at child apex: {child}")
    return records


def update_parent_ds_from_cds(child: str) -> None:
    ds_records = cds_rrset_from_child(child)
    path = ZONES / "com" / "db.com"
    lines = path.read_text(encoding="ascii").splitlines()
    child_lhs = child.rstrip(".") + "."
    kept = [line for line in lines if not re.match(rf"^{re.escape(child_lhs)}\s+.*\sIN\s+DS\s+", line)]
    kept.extend(ds_records)
    path.write_text("\n".join(kept) + "\n", encoding="ascii")
    log("parent automation installed DS from child CDS:")
    for record in ds_records:
        log("  " + record)
    sign_zone("com", "good")
    restart()


def receive_dsync_notify_once() -> None:
    import dns.message
    import dns.opcode
    import dns.rdatatype

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((AUTH["com"]["ip"], DSYNC_PORT))
    sock.settimeout(10)
    log(f"DSYNC receiver listening on {AUTH['com']['ip']}:{DSYNC_PORT}")
    try:
        wire, addr = sock.recvfrom(4096)
        msg = dns.message.from_wire(wire)
        response = dns.message.make_response(msg)
        sock.sendto(response.to_wire(), addr)
        if msg.opcode() != dns.opcode.NOTIFY:
            raise RuntimeError("received packet is not DNS NOTIFY")
        question = msg.question[0]
        child = question.name.to_text()
        if question.rdtype != dns.rdatatype.CDS:
            raise RuntimeError(f"unexpected NOTIFY qtype: {dns.rdatatype.to_text(question.rdtype)}")
        log(f"received NOTIFY(CDS) for {child} from {addr[0]}:{addr[1]}")
        update_parent_ds_from_cds(child)
    finally:
        sock.close()


def send_dsync_notify(child: str) -> None:
    import dns.message
    import dns.opcode
    import dns.query
    import dns.rdatatype

    msg = dns.message.make_query(child, dns.rdatatype.CDS)
    msg.set_opcode(dns.opcode.NOTIFY)
    log(f"sending NOTIFY(CDS) for {child} to parent DSYNC endpoint {AUTH['com']['ip']}:{DSYNC_PORT}")
    dns.query.udp(msg, AUTH["com"]["ip"], port=DSYNC_PORT, timeout=3)


def dsync_demo() -> None:
    require_tools()
    reset_workdir()
    build_dsync_bootstrap_zones()
    write_named_configs()
    start()

    log("parent publishes DSYNC endpoint")
    run(["dig", f"@{AUTH['com']['ip']}", "example.com._dsync.com.", "TYPE66", "+short"])
    log("before NOTIFY, parent has no example.com DS")
    run(["dig", f"@{AUTH['com']['ip']}", "example.com.", "DS", "+dnssec", "+multi"])

    receiver = Thread(target=receive_dsync_notify_once, daemon=True)
    receiver.start()
    time.sleep(0.5)
    send_dsync_notify("example.com.")
    receiver.join(timeout=15)
    if receiver.is_alive():
        raise SystemExit("DSYNC receiver did not finish")

    log("after NOTIFY, parent has installed example.com DS")
    run(["dig", f"@{AUTH['com']['ip']}", "example.com.", "DS", "+dnssec", "+multi"])
    log("resolver response after DS bootstrapping")
    dig_check()


def named_conf_auth(name: str) -> str:
    meta = AUTH[name]
    return f"""
options {{
    directory "{WORK}";
    listen-on port 53 {{ {meta["ip"]}; }};
    listen-on-v6 {{ none; }};
    recursion no;
    dnssec-validation no;
    allow-query {{ any; }};
    pid-file "{RUN / (name + ".pid")}";
    session-keyfile "{RUN / (name + ".session.key")}";
}};

controls {{}};

zone "{meta["zone"]}" IN {{
    type master;
    file "{ZONES / name / (meta["file"] + ".signed")}";
}};
"""


def named_conf_resolver() -> str:
    hints = CONF / "root.hints"
    hints.write_text(
        f""". 3600 IN NS ns.root.
ns.root. 3600 IN A {AUTH["root"]["ip"]}
""",
        encoding="ascii",
    )
    return f"""
options {{
    directory "{WORK}";
    listen-on port 53 {{ {RESOLVER_IP}; }};
    listen-on-v6 {{ none; }};
    recursion yes;
    dnssec-validation yes;
    allow-query {{ any; }};
    pid-file "{RUN / "resolver.pid"}";
    session-keyfile "{RUN / "resolver.session.key"}";
}};

controls {{}};

{root_trust_anchor()}

zone "." IN {{
    type hint;
    file "{hints}";
}};
"""


def write_named_configs() -> None:
    for name in AUTH:
        path = CONF / f"named-{name}.conf"
        path.write_text(named_conf_auth(name), encoding="ascii")
        run(["named-checkconf", str(path)])
    resolver = CONF / "named-resolver.conf"
    resolver.write_text(named_conf_resolver(), encoding="ascii")
    run(["named-checkconf", str(resolver)])


def setup(scenario: str) -> None:
    if scenario not in SCENARIOS:
        raise SystemExit(f"unknown scenario: {scenario}")
    require_tools()
    reset_workdir()
    build_zones(scenario)
    write_named_configs()
    start()
    log(f"scenario ready: {scenario}")


def start() -> None:
    stop(quiet=True)
    ensure_loopback_ips()
    # Debian's named drops to the bind user even when launched via sudo.  The
    # lab uses throwaway files, so broad write permissions are acceptable here.
    run(["chmod", "-R", "a+rwX", str(WORK)], sudo=True)
    for name in ["root", "com", "example"]:
        conf = CONF / f"named-{name}.conf"
        log(f"starting authoritative {AUTH[name]['zone']} on {AUTH[name]['ip']}:53")
        run(["named", "-n", "1", "-4", "-c", str(conf)], sudo=True)
    log(f"starting validating resolver on {RESOLVER_IP}:53")
    run(["named", "-n", "1", "-4", "-c", str(CONF / "named-resolver.conf")], sudo=True)
    wait_until_listening()


def ensure_loopback_ips() -> None:
    ips = [AUTH[name]["ip"] for name in ["root", "com", "example"]] + [RESOLVER_IP]
    current = run(["ip", "-4", "addr", "show", "dev", "lo"], capture=True).stdout
    for ip in ips:
        if f"{ip}/32" not in current and f"{ip}/8" not in current:
            run(["ip", "addr", "add", f"{ip}/32", "dev", "lo"], sudo=True, check=False)


def wait_until_listening() -> None:
    ips = [AUTH[name]["ip"] for name in ["root", "com", "example"]] + [RESOLVER_IP]
    deadline = time.time() + 10
    pending = set(ips)
    while pending and time.time() < deadline:
        for ip in list(pending):
            try:
                with socket.create_connection((ip, 53), timeout=0.5):
                    pass
                pending.discard(ip)
            except OSError:
                pass
        if pending:
            time.sleep(0.25)
    if pending:
        raise SystemExit("BIND did not start listening on: " + ", ".join(sorted(pending)))


def read_pid(path: Path):
    try:
        return int(path.read_text().strip())
    except Exception:
        return None


def stop(quiet=False) -> None:
    if not RUN.exists():
        return
    for pidfile in RUN.glob("*.pid"):
        pid = read_pid(pidfile)
        if not pid:
            continue
        if not quiet:
            log(f"stopping pid {pid} ({pidfile.name})")
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except PermissionError:
            run(["kill", str(pid)], sudo=True, check=False)
        pidfile.unlink(missing_ok=True)
    time.sleep(0.5)


def restart() -> None:
    start()


def dig_check() -> None:
    run(["dig", f"@{RESOLVER_IP}", "www." + AUTH["example"]["zone"], "A", "+dnssec", "+multi"])


def dnsviz(prefix: str) -> None:
    raw = OUT / f"{prefix}.probe.json"
    grok = OUT / f"{prefix}.grok.json"
    env = dnsviz_env()
    scenario = prefix.rsplit(".", 1)[0]
    config = get_scenario(scenario)
    qname = lab_name(config.qname) if config else "www." + AUTH["example"]["zone"]
    rrtypes = config.rrtypes if config else None
    example_auth = AUTH["example"]["ip"]
    if scenario in {
        "dnskey-missing-from-servers",
        "existing-name-covered",
        "existing-type-not-in-bitmap",
        "multiple-cds",
        "multiple-cdnskey",
    }:
        example_auth = f"{example_auth},127.10.0.4"
    probe_cmd = [
        "dnsviz",
        "probe",
        "-A",
        "-a",
        AUTH["com"]["zone"],
        "-x",
        f"{AUTH['com']['zone']}+:{AUTH['com']['ip']}",
        "-x",
        f"{AUTH['example']['zone']}:{example_auth}",
        "-o",
        str(raw),
    ]
    if rrtypes:
        probe_cmd.extend(["-R", rrtypes])
    probe_cmd.append(qname)
    run(
        probe_cmd,
        env=env,
    )
    run(["dnsviz", "grok", "-P", "-r", str(raw), "-t", str(OUT / "trusted.keys"), "-o", str(grok)], env=env)
    log(f"wrote {raw}")
    log(f"wrote {grok}")
    print_error_codes(grok)


def safe_label(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value.rstrip(".")).strip(".-") or "realcase"


def dnsviz_live_domain(domain: str, *, qname: str | None = None, out_dir: Path | None = None) -> Path:
    """Capture current public DNSViz state for a real domain.

    This is best-effort live input. The local lab repair still runs against the
    normalized example.com. topology, but the returned grok preserves the real
    domain evidence for import/record output.
    """
    require_tools()
    for directory in [WORK, OUT, SHIM]:
        directory.mkdir(parents=True, exist_ok=True)

    domain = domain if domain.endswith(".") else domain + "."
    qname = qname or domain
    qname = qname if qname.endswith(".") else qname + "."
    out_dir = out_dir or (ROOT / "realcase-live" / safe_label(domain))
    out_dir.mkdir(parents=True, exist_ok=True)
    raw = out_dir / f"{safe_label(qname)}.live.probe.json"
    grok = out_dir / f"{safe_label(qname)}.live.grok.json"
    env = dnsviz_env()

    log(f"capturing live DNSViz state for {qname} (source domain {domain})")
    log("this step uses public DNS; if the devbox has no outbound DNS connectivity, use an offline grok instead")
    grok_cmd = ["dnsviz", "grok", "-r", str(raw), "-o", str(grok)]
    system_root_key = Path("/usr/share/dns/root.key")
    if system_root_key.exists():
        grok_cmd[2:2] = ["-t", str(system_root_key)]

    try:
        run(["dnsviz", "probe", "-A", "-4", "-o", str(raw), qname], env=env)
        run(grok_cmd, env=env)
    except SystemExit as exc:
        raise SystemExit(
            f"live DNSViz capture failed for {qname}. "
            "The devbox may not have public DNS connectivity; use an existing --grok/import-realcase path instead."
        ) from exc
    log(f"wrote live probe {raw}")
    log(f"wrote live grok {grok}")
    print_error_codes(grok)
    data = json.loads(grok.read_text(encoding="utf-8"))
    if data and all(isinstance(item, dict) and item.get("status") == "INDETERMINATE" for item in data.values()):
        log("live DNSViz result is INDETERMINATE only; public DNS connectivity may be incomplete")
    return grok


def collect_codes(obj):
    codes = []
    if isinstance(obj, dict):
        code = obj.get("code")
        if isinstance(code, str):
            codes.append(code)
        for val in obj.values():
            codes.extend(collect_codes(val))
    elif isinstance(obj, list):
        for val in obj:
            codes.extend(collect_codes(val))
    return codes


def print_error_codes(grok: Path) -> None:
    data = json.loads(grok.read_text())
    codes = sorted(set(collect_codes(data)))
    if codes:
        log("DNSViz error codes: " + ", ".join(codes))
    else:
        log("DNSViz error codes: <none>")


def ensure_local_dnsviz_config() -> None:
    repo = local_dnsviz_repo()
    if repo is None:
        return
    config = repo / "dnsviz" / "config.py"
    if config.exists():
        return
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(
        """from __future__ import unicode_literals\n"""
        """import os\n"""
        """DNSVIZ_INSTALL_PREFIX = ''\n"""
        """DNSVIZ_SHARE_PATH = os.getenv('DNSVIZ_SHARE_PATH', os.path.join(DNSVIZ_INSTALL_PREFIX, 'share', 'dnsviz'))\n"""
        """JQUERY_PATH = 'https://code.jquery.com/jquery-1.11.3.min.js'\n"""
        """JQUERY_UI_PATH = 'https://code.jquery.com/ui/1.11.4/jquery-ui.min.js'\n"""
        """JQUERY_UI_CSS_PATH = 'https://code.jquery.com/ui/1.11.4/themes/redmond/jquery-ui.css'\n"""
        """RAPHAEL_PATH = 'https://cdnjs.cloudflare.com/ajax/libs/raphael/2.1.4/raphael-min.js'\n"""
        """RESOLV_CONF = '/etc/resolv.conf'\n""",
        encoding="ascii",
    )


def local_dnsviz_repo() -> Path | None:
    for repo in DNSVIZ_REPO_CANDIDATES:
        if (repo / "dnsviz").is_dir():
            return repo
    return None


def dnsviz_env():
    # Prefer a local DNSViz source tree when present; otherwise use the
    # system-installed dnsviz command from PATH.
    ensure_local_dnsviz_config()
    sitecustomize = SHIM / "sitecustomize.py"
    sitecustomize.write_text(
        """import sys, types\ntry:\n    import pygraphviz\n    m = types.ModuleType('pygraphviz.release')\n    m.version = getattr(pygraphviz, '__version__', '1.7')\n    sys.modules.setdefault('pygraphviz.release', m)\nexcept Exception:\n    pass\n""",
        encoding="ascii",
    )
    env = os.environ.copy()
    paths = [str(SHIM)]
    repo = local_dnsviz_repo()
    if repo is not None:
        paths.append(str(repo))
    if env.get("PYTHONPATH"):
        paths.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(paths)
    return env


def latest_grok() -> Path:
    files = sorted(OUT.glob("*.grok.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        raise SystemExit("no grok output found; run diagnose first")
    return files[0]


def fix(scenario: str) -> None:
    import dnssec_repair_engine

    dnssec_repair_engine.execute_scenario_repair("bind9", scenario)


def apply_scenario_fix(scenario: str) -> None:
    context = LabContext()
    config = get_scenario(scenario)
    if not config:
        raise SystemExit(f"fix does not know scenario: {scenario}")
    if config.before_fix:
        config.before_fix(context)
    log(config.fix_message)
    # Rebuild with the same keys but no injected error.
    write_zone_files("good")
    sign_zone("example", "good")
    sign_zone("com", "good")
    sign_zone("root", "good")
    restart()


def demo(scenario: str, domain: str | None = None) -> None:
    import dnssec_repair_engine

    try:
        if domain:
            source_domain = domain if domain.endswith(".") else domain + "."
            log(f"source domain: {source_domain}")
            log(f"local lab zones: child={AUTH['example']['zone']} parent={AUTH['com']['zone']}")
        setup(scenario)
        log("baseline resolver response")
        dig_check()
        log("running DNSViz before repair")
        dnsviz(f"{scenario}.before")
        log("local repair engine plan")
        plan = dnssec_repair_engine.plan_scenario("bind9", scenario)
        dnssec_repair_engine.write_plan(plan, OUT / f"{scenario}.repair-plan.json")
        print(json.dumps(dnssec_repair_engine.plan_as_dict(plan), ensure_ascii=False, indent=2))
        log("applying local lab repair")
        fix(scenario)
        log("running DNSViz after repair")
        dnsviz(f"{scenario}.after")
        log("final resolver response")
        dig_check()
    finally:
        stop(quiet=True)
        log("stopped local DNS services")


def realcase_demo(
    scenario: str,
    *,
    domain: str,
    qname: str | None = None,
    backend: str = "bind9",
    out_dir: Path | None = None,
) -> None:
    import lab_config_exporter
    import realcase_chain_importer

    def stop_realcase_services() -> None:
        stop(quiet=True)
        if backend == "powerdns":
            try:
                import powerdns_lab

                powerdns_lab.stop(quiet=True)
            except (Exception, SystemExit) as exc:
                log(f"PowerDNS cleanup skipped: {exc}")

    domain = domain if domain.endswith(".") else domain + "."
    out_dir = out_dir or (ROOT / "realcase-live" / safe_label(domain))
    backend = backend.lower()
    live_grok = None
    try:
        live_grok = dnsviz_live_domain(domain, qname=qname, out_dir=out_dir)
    except (Exception, SystemExit) as exc:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "live-capture-error.txt").write_text(str(exc) + "\n", encoding="utf-8")
        log(f"live DNSViz capture skipped: {exc}")
        log("continuing with source-shaped local scenario demo")

    if live_grok is not None:
        log("importing live DNSViz records into local realcase package")
    try:
        if live_grok is None:
            raise RuntimeError("no live grok available")
        result = realcase_chain_importer.import_realcase(
            live_grok,
            backend=backend,
            domain=domain,
            out_dir=out_dir / "import",
        )
        log(f"live import package: {result.out_dir}")
    except (Exception, SystemExit) as exc:
        log(f"live import skipped: {exc}")
        log("continuing with source-shaped local scenario demo")
    configure_lab_zones(domain)
    log(f"starting local repair demo with child={AUTH['example']['zone']} parent={AUTH['com']['zone']}")
    try:
        if backend == "bind9":
            demo(scenario, domain=domain)
        elif backend == "powerdns":
            import powerdns_lab

            log(f"source domain: {domain}")
            log(f"local lab zones: child={AUTH['example']['zone']} parent={AUTH['com']['zone']}")
            powerdns_lab.demo(scenario)
        else:
            raise SystemExit(f"unsupported backend: {backend}")
        bundle = lab_config_exporter.export_config_bundle(
            backend,
            out_dir,
            source_domain=domain,
            purpose="repair DNSSEC deployment errors locally from public resolution-chain records",
        )
        log(f"exported readable {backend} config bundle: {bundle}")
    finally:
        stop_realcase_services()
        log("stopped local DNS services")


def repair_realcase(
    *,
    domain: str,
    qname: str | None = None,
    backend: str = "bind9",
    out_dir: Path | None = None,
    grok: Path | None = None,
    zone_file: Path | None = None,
    axfr_server: str | None = None,
    axfr_port: int = 53,
    allow_partial_records: bool = False,
    rotate_keys: bool = False,
    verify: bool = True,
) -> RealcaseRepairResult:
    import controlled_dnssec_deploy as deploy
    import controlled_zone_repair
    import dnsviz_grok_adapter
    import dnssec_repair_engine as repair
    import lab_config_exporter
    import realcase_chain_importer

    backend = repair.normalize_backend(backend)
    domain = absolute_name(domain)
    out_dir = out_dir or (ROOT / "realcase-live" / safe_label(domain))
    out_dir.mkdir(parents=True, exist_ok=True)
    if grok is None:
        grok = dnsviz_live_domain(domain, qname=qname, out_dir=out_dir)
    elif not grok.is_file():
        raise SystemExit(f"DNSViz grok file does not exist: {grok}")

    diagnosis = dnsviz_grok_adapter.diagnose_grok(grok, backend)
    if absolute_name(diagnosis.zone).lower() != domain.lower():
        raise SystemExit(
            f"DNSViz capture describes zone {diagnosis.zone}, not requested domain {domain}; "
            "use the diagnosed zone as --domain"
        )

    configure_lab_zones(domain, diagnosis.parent_zone or parent_zone_for(domain))
    qnames = (qname,) if qname else None
    record_import = deploy.acquire_business_records(
        domain,
        qnames=qnames,
        zone_file=zone_file,
        axfr_server=axfr_server,
        axfr_port=axfr_port,
        allow_partial_records=allow_partial_records,
    )
    imported = realcase_chain_importer.import_realcase(
        grok,
        backend=backend,
        domain=domain,
        out_dir=out_dir / "import",
    )

    actions = list(deploy.setup_unsigned_lab(backend))
    deploy.write_unsigned_child_with_records(record_import.records)
    actions.append(f"import {len(record_import.records)} business record(s) from {record_import.source}")
    deploy.publish_child_ds_to_parent()
    actions.append("publish locally generated child DS into the controlled parent")
    deploy.sign_deployed_chain()
    deploy.start_backend(backend)
    actions.append(f"start controlled {backend} authority chain")

    local_verify_grok = None
    local_final_codes: tuple[str, ...] = ()
    try:
        repaired = controlled_zone_repair.repair_backend_from_grok(
            backend,
            grok,
            rotate_keys=rotate_keys,
        )
        actions.extend(repaired.actions)
        if verify:
            verified_grok, local_final_codes = deploy.verify_deployment(
                f"repair-realcase-{safe_label(domain)}"
            )
            local_verify_grok = str(verified_grok)
            actions.append("verify the controlled local chain with DNSViz")

        files = dict(imported.files)
        files["import_summary"] = files.pop("summary")
        files["local_verify_grok"] = local_verify_grok or ""
        files["config_bundle"] = lab_config_exporter.export_config_bundle(
            backend,
            out_dir,
            source_domain=domain,
            purpose="apply a live DNSViz-derived repair plan to a controlled local clone",
        )
        summary = out_dir / "repair-realcase-summary.json"
        files["summary"] = str(summary)
        result = RealcaseRepairResult(
            source_domain=domain,
            backend=backend,
            live_grok=str(grok),
            observed_codes=diagnosis.error_codes,
            repair_plan=repair.plan_as_dict(repair.build_plan(diagnosis.to_context())),
            record_source=record_import.source,
            records_complete=record_import.complete,
            record_warnings=record_import.warnings,
            imported_record_count=len(record_import.records),
            actions=tuple(actions),
            local_verify_grok=local_verify_grok,
            local_final_codes=local_final_codes,
            local_converged=not local_final_codes if verify else None,
            verification_scope="local-controlled",
            public_changes_applied=False,
            files=files,
        )
        summary.write_text(json.dumps(asdict(result), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return result
    finally:
        deploy.stop_backend(backend)


def main() -> None:
    parser = argparse.ArgumentParser(description="Local DNSSEC/BIND9 lab for DNSViz-driven deploy and repair experiments")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("setup")
    p.add_argument("scenario", choices=sorted(SCENARIOS))
    sub.add_parser("start")
    sub.add_parser("stop")
    sub.add_parser("restart")
    sub.add_parser("dig")
    p = sub.add_parser("diagnose")
    p.add_argument("--prefix", default="manual")
    p = sub.add_parser("fix")
    p.add_argument("scenario", choices=FIXABLE_SCENARIOS)
    p = sub.add_parser("demo")
    p.add_argument("scenario", choices=FIXABLE_SCENARIOS)
    p.add_argument("--domain", default=None, help="real source domain label shown in demo logs for built-in fixed-zone scenarios")
    p = sub.add_parser("realcase-demo")
    p.add_argument("scenario", choices=FIXABLE_SCENARIOS)
    p.add_argument("--domain", required=True, help="real domain to capture with DNSViz before running the normalized lab demo")
    p.add_argument("--qname", default=None, help="specific real qname to probe; defaults to --domain")
    p.add_argument("--backend", choices=["bind9", "powerdns"], default="bind9", help="backend label for generated repair plan")
    p.add_argument("--out-dir", type=Path, default=None, help="directory for live probe/grok and imported record package")
    p = sub.add_parser("repair-realcase")
    p.add_argument("--domain", required=True, help="real domain to capture and reproduce in the controlled lab")
    p.add_argument("--qname", default=None, help="specific real qname to probe; defaults to --domain")
    p.add_argument("--backend", choices=["bind9", "powerdns"], default="bind9", help="backend label for generated repair plan")
    p.add_argument("--out-dir", type=Path, default=None, help="directory for live probe/grok and imported record package")
    p.add_argument("--grok", type=Path, default=None, help="existing DNSViz grok JSON; skips live capture")
    p.add_argument("--zone-file", type=Path, default=None, help="authoritative zone export used as the complete record source")
    p.add_argument("--axfr-server", default=None, help="authoritative server that permits AXFR")
    p.add_argument("--axfr-port", type=int, default=53)
    p.add_argument("--allow-partial-records", action="store_true", help="allow an incomplete recursive-DNS sample for lab-only use")
    p.add_argument("--rotate-keys", action="store_true")
    p.add_argument("--no-verify", action="store_true")
    p.add_argument("--out", type=Path, default=None)
    sub.add_parser("dsync-demo")
    args = parser.parse_args()

    if args.cmd == "setup":
        setup(args.scenario)
    elif args.cmd == "start":
        start()
    elif args.cmd == "stop":
        stop()
    elif args.cmd == "restart":
        restart()
    elif args.cmd == "dig":
        dig_check()
    elif args.cmd == "diagnose":
        dnsviz(args.prefix)
    elif args.cmd == "fix":
        fix(args.scenario)
    elif args.cmd == "demo":
        demo(args.scenario, domain=args.domain)
    elif args.cmd == "realcase-demo":
        realcase_demo(args.scenario, domain=args.domain, qname=args.qname, backend=args.backend, out_dir=args.out_dir)
    elif args.cmd == "repair-realcase":
        result = repair_realcase(
            domain=args.domain,
            qname=args.qname,
            backend=args.backend,
            out_dir=args.out_dir,
            grok=args.grok,
            zone_file=args.zone_file,
            axfr_server=args.axfr_server,
            axfr_port=args.axfr_port,
            allow_partial_records=args.allow_partial_records,
            rotate_keys=args.rotate_keys,
            verify=not args.no_verify,
        )
        text = json.dumps(asdict(result), ensure_ascii=False, indent=2)
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(text + "\n", encoding="utf-8")
        print(text)
        if result.local_converged is False:
            raise SystemExit(1)
    elif args.cmd == "dsync-demo":
        dsync_demo()


if __name__ == "__main__":
    main()

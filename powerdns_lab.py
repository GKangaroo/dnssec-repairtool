#!/usr/bin/env python3
import argparse
import json
import os
import signal
import socket
import shutil
import subprocess
import sys
import time
from pathlib import Path

import dnssec_lab as bind_lab
from dnssec_scenarios import SCENARIOS as ERROR_SCENARIOS


ROOT = bind_lab.ROOT
WORK = bind_lab.WORK
CONF = bind_lab.CONF
RUN = bind_lab.RUN
ZONES = bind_lab.ZONES
AUTH = bind_lab.AUTH
RESOLVER_IP = bind_lab.RESOLVER_IP
PDNS_RUN = Path(f"/tmp/dnssec-pdns-{os.getuid()}")
SCENARIOS = {"good", *ERROR_SCENARIOS}
FIXABLE_SCENARIOS = sorted(SCENARIOS - {"good"})
EXAMPLE_NS2_IP = "127.10.0.4"
MULTI_AUTH_SCENARIOS = {
    "dnskey-missing-from-servers",
    "existing-name-covered",
    "existing-type-not-in-bitmap",
    "multiple-cds",
    "multiple-cdnskey",
}

NSEC3_SCENARIO_PARAMS = {
    "no-closest-encloser": "1 0 0 -",
    "no-nsec3-matching-sname": "1 0 0 -",
    "nonempty-nsec3-salt": "1 0 0 A1",
    "nonzero-nsec3-iteration-count": "1 0 1 A1",
    "wildcard-covered": "1 0 0 -",
    "wildcard-not-covered": "1 0 0 -",
}


def log(msg: str) -> None:
    print(f"[powerdns-lab] {msg}", flush=True)


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
    bind_lab.require_tools()
    missing = [tool for tool in ["pdns_server", "pdnsutil"] if shutil.which(tool) is None]
    if missing:
        raise SystemExit("missing PowerDNS tools: " + ", ".join(missing))


def read_pid(path: Path):
    try:
        return int(path.read_text().strip())
    except Exception:
        return None


def stop(quiet=False) -> None:
    for run_dir in (RUN, PDNS_RUN):
        if not run_dir.exists():
            continue
        for pidfile in run_dir.glob("*.pid"):
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


def pdns_instances(scenario: str | None = None) -> list[tuple[str, dict]]:
    instances = [(name, dict(meta)) for name, meta in AUTH.items()]
    if scenario in MULTI_AUTH_SCENARIOS:
        instances.append(
            (
                "example2",
                {
                    "zone": AUTH["example"]["zone"],
                    "ip": EXAMPLE_NS2_IP,
                    "file": "db.example.com.ns2",
                    "zone_dir": "example",
                },
            )
        )
    return instances


def write_pdns_bind_configs(scenario: str | None = None) -> None:
    for name, meta in pdns_instances(scenario):
        zone_dir = meta.get("zone_dir", name)
        bind_conf = CONF / f"pdns-{name}-zones.conf"
        dnssec_db = WORK / f"pdns-{name}-dnssec.sqlite3"
        bind_conf.write_text(
            f"""zone "{meta['zone']}" IN {{
    type master;
    file "{ZONES / zone_dir / (meta['file'] + '.signed')}";
}};
""",
            encoding="ascii",
        )

        PDNS_RUN.mkdir(parents=True, exist_ok=True)
        pdns_conf = CONF / f"pdns-{name}.conf"
        pdns_conf.write_text(
            f"""daemon=yes
guardian=no
local-address={meta['ip']}
local-port=53
launch=bind
bind-config={bind_conf}
bind-check-interval=0
bind-dnssec-db={dnssec_db}
direct-dnskey=yes
include-dir=
setgid=
setuid=
socket-dir={PDNS_RUN}
write-pid=yes
webserver=no
version-string=anonymous
""",
            encoding="ascii",
        )


def write_pdns_dnssec_metadata(scenario: str | None = None) -> None:
    for name, meta in pdns_instances(scenario):
        dnssec_db = WORK / f"pdns-{name}-dnssec.sqlite3"
        dnssec_db.unlink(missing_ok=True)
        run(["pdnsutil", "--config-dir", str(CONF), "--config-name", name, "create-bind-db", str(dnssec_db)])
        run(["pdnsutil", "--config-dir", str(CONF), "--config-name", name, "set-presigned", meta["zone"]])
        if meta["zone"] == AUTH["example"]["zone"] and scenario in NSEC3_SCENARIO_PARAMS:
            run(
                [
                    "pdnsutil",
                    "--config-dir",
                    str(CONF),
                    "--config-name",
                    name,
                    "set-nsec3",
                    meta["zone"],
                    NSEC3_SCENARIO_PARAMS[scenario],
                ]
            )


def setup(scenario: str) -> None:
    if scenario not in SCENARIOS:
        raise SystemExit(f"unknown scenario: {scenario}")
    require_tools()
    stop(quiet=True)
    bind_lab.reset_workdir()
    bind_lab.build_zones(scenario)
    write_pdns_bind_configs(scenario)
    write_pdns_dnssec_metadata(scenario)
    resolver = CONF / "named-resolver.conf"
    resolver.write_text(bind_lab.named_conf_resolver(), encoding="ascii")
    run(["named-checkconf", str(resolver)])
    start(scenario)
    wait_until_multi_auth_variant_ready(scenario)
    log(f"scenario ready: {scenario}")


def ensure_loopback_ips(scenario: str | None = None) -> None:
    bind_lab.ensure_loopback_ips()
    if scenario in MULTI_AUTH_SCENARIOS:
        current = run(["ip", "-4", "addr", "show", "dev", "lo"], capture=True).stdout
        if f"{EXAMPLE_NS2_IP}/32" not in current and f"{EXAMPLE_NS2_IP}/8" not in current:
            run(["ip", "addr", "add", f"{EXAMPLE_NS2_IP}/32", "dev", "lo"], sudo=True, check=False)


def start(scenario: str | None = None) -> None:
    stop(quiet=True)
    ensure_loopback_ips(scenario)
    run(["chmod", "-R", "a+rwX", str(WORK)], sudo=True)
    PDNS_RUN.mkdir(parents=True, exist_ok=True)
    run(["chmod", "-R", "a+rwX", str(PDNS_RUN)], sudo=True)
    for name, meta in pdns_instances(scenario):
        conf = CONF / f"pdns-{name}.conf"
        log(f"starting PowerDNS authoritative {meta['zone']} on {meta['ip']}:53")
        run(["pdns_server", f"--config-dir={CONF}", f"--config-name={name}"], sudo=True)
    log(f"starting BIND validating resolver on {RESOLVER_IP}:53")
    run(["named", "-n", "1", "-4", "-c", str(CONF / "named-resolver.conf")], sudo=True)
    wait_until_listening(scenario)


def wait_until_listening(scenario: str | None = None) -> None:
    ips = [meta["ip"] for _, meta in pdns_instances(scenario)] + [RESOLVER_IP]
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
        raise SystemExit("PowerDNS/BIND did not start listening on: " + ", ".join(sorted(pending)))


def query_rdata_lines(server: str, rrtype: str) -> list[str]:
    proc = run(
        ["dig", f"@{server}", "example.com.", rrtype, "+dnssec", "+noall", "+answer"],
        capture=True,
        check=False,
    )
    lines = []
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        parts = stripped.split()
        if len(parts) >= 4 and parts[3] == rrtype:
            lines.append(stripped)
    return lines


def query_name_rdata_lines(server: str, qname: str, rrtype: str) -> list[str]:
    proc = run(
        ["dig", f"@{server}", qname, rrtype, "+dnssec", "+noall", "+answer"],
        capture=True,
        check=False,
    )
    lines = []
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        parts = stripped.split()
        if len(parts) >= 4 and parts[0].rstrip(".") == qname.rstrip(".") and parts[3] == rrtype:
            lines.append(stripped)
    return lines


def wait_until_multi_auth_variant_ready(scenario: str) -> None:
    if scenario not in MULTI_AUTH_SCENARIOS:
        return
    if scenario in {"existing-name-covered", "existing-type-not-in-bitmap"}:
        qname = {
            "existing-name-covered": "www.example.com.",
            "existing-type-not-in-bitmap": "www.example.com.",
        }[scenario]
        deadline = time.time() + 10
        while time.time() < deadline:
            primary = query_name_rdata_lines(AUTH["example"]["ip"], qname, "A")
            secondary = query_name_rdata_lines(EXAMPLE_NS2_IP, qname, "A")
            if scenario == "existing-type-not-in-bitmap":
                secondary_txt = query_name_rdata_lines(EXAMPLE_NS2_IP, qname, "TXT")
                if primary and not secondary and secondary_txt:
                    return
            elif primary and not secondary:
                return
            time.sleep(0.25)
        raise SystemExit(f"multi-auth variant not ready for {scenario}")
    rrtype = {
        "dnskey-missing-from-servers": "DNSKEY",
        "multiple-cds": "CDS",
        "multiple-cdnskey": "CDNSKEY",
    }[scenario]
    deadline = time.time() + 10
    while time.time() < deadline:
        primary = query_rdata_lines(AUTH["example"]["ip"], rrtype)
        secondary = query_rdata_lines(EXAMPLE_NS2_IP, rrtype)
        if primary and secondary and primary != secondary:
            return
        time.sleep(0.25)
    raise SystemExit(f"multi-auth variant not ready for {scenario}")


def restart() -> None:
    start()


def add_example_ns2_records() -> None:
    example_zone = bind_lab.LabContext().unsigned_zone_path("example")
    with example_zone.open("a", encoding="ascii") as fh:
        fh.write(f"\n@ IN NS ns2.example.com.\nns2 IN A {EXAMPLE_NS2_IP}\n")

    com_zone = bind_lab.LabContext().unsigned_zone_path("com")
    with com_zone.open("a", encoding="ascii") as fh:
        fh.write(f"\nexample.com. IN NS ns2.example.com.\nns2.example.com. IN A {EXAMPLE_NS2_IP}\n")


def fix_multi_auth_scenario(scenario: str) -> None:
    bind_lab.write_zone_files("good")
    context = bind_lab.LabContext()
    if scenario == "multiple-cds":
        context.append_cds(context.unsigned_zone_path("example"))
    elif scenario == "multiple-cdnskey":
        context.append_cdnskey(context.unsigned_zone_path("example"))
    add_example_ns2_records()
    bind_lab.sign_zone("example", "good")
    primary = context.signed_zone_path("example")
    secondary = primary.with_name("db.example.com.ns2.signed")
    shutil.copyfile(primary, secondary)
    bind_lab.sign_zone("com", "good")
    bind_lab.sign_zone("root", "good")
    write_pdns_bind_configs(scenario)
    write_pdns_dnssec_metadata(scenario)
    start(scenario)


def fix(scenario: str) -> None:
    import dnssec_repair_engine

    dnssec_repair_engine.execute_scenario_repair("powerdns", scenario)


def apply_scenario_fix(scenario: str) -> None:
    config = bind_lab.get_scenario(scenario)
    if not config:
        raise SystemExit(f"fix does not know scenario: {scenario}")
    if config.before_fix:
        config.before_fix(bind_lab.LabContext())
    log(config.fix_message)
    if scenario in MULTI_AUTH_SCENARIOS:
        fix_multi_auth_scenario(scenario)
        return
    bind_lab.write_zone_files("good")
    bind_lab.sign_zone("example", "good")
    bind_lab.sign_zone("com", "good")
    bind_lab.sign_zone("root", "good")
    stop(quiet=True)
    write_pdns_bind_configs()
    write_pdns_dnssec_metadata()
    start()


def demo(scenario: str) -> None:
    import dnssec_repair_engine

    try:
        setup(scenario)
        log("baseline resolver response")
        bind_lab.dig_check()
        log("running DNSViz before repair")
        bind_lab.dnsviz(f"{scenario}.before")
        log("local repair engine plan")
        plan = dnssec_repair_engine.plan_scenario("powerdns", scenario)
        dnssec_repair_engine.write_plan(plan, bind_lab.OUT / f"{scenario}.repair-plan.json")
        print(json.dumps(dnssec_repair_engine.plan_as_dict(plan), ensure_ascii=False, indent=2))
        log("applying local lab repair")
        fix(scenario)
        log("running DNSViz after repair")
        bind_lab.dnsviz(f"{scenario}.after")
        log("final resolver response")
        bind_lab.dig_check()
    finally:
        stop(quiet=True)
        log("stopped local DNS services")


def main() -> None:
    parser = argparse.ArgumentParser(description="Local DNSSEC/PowerDNS authoritative lab for DNSViz-driven deploy and repair experiments")
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
        bind_lab.dig_check()
    elif args.cmd == "diagnose":
        bind_lab.dnsviz(args.prefix)
    elif args.cmd == "fix":
        fix(args.scenario)
    elif args.cmd == "demo":
        demo(args.scenario)


if __name__ == "__main__":
    main()

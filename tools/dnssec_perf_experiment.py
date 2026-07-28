#!/usr/bin/env python3
"""Benchmark validating vs non-validating recursive resolvers in the local lab."""

from __future__ import annotations

import argparse
import random
import selectors
import socket
import statistics
import struct
import sys
import time
from pathlib import Path

LAB_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB_ROOT))

import dnssec_lab


TIER_VALIDATING_BACKENDS = ["127.10.0.61", "127.10.0.62"]
TIER_NO_VALIDATE_BACKENDS = ["127.10.0.63", "127.10.0.64"]
TIER_VALIDATING_CACHES = ["127.10.0.51", "127.10.0.52"]
TIER_NO_VALIDATE_CACHES = ["127.10.0.55", "127.10.0.56"]
PORT = 53


def setup_perf_zone(records: int) -> None:
    dnssec_lab.require_tools()
    dnssec_lab.reset_workdir()
    dnssec_lab.ensure_keys()

    example_ds = dnssec_lab.ds_from_ksk("example")
    com_ds = dnssec_lab.ds_from_ksk("com")

    hosts = "\n".join(f"host-{i} IN A 192.0.2.{(i % 250) + 1}" for i in range(records))
    (dnssec_lab.ZONES / "example" / "db.example.com").write_text(
        f"""$ORIGIN example.com.
$TTL 300
@ IN SOA ns.example.com. hostmaster.example.com. (
    {dnssec_lab.SERIAL} 300 300 1200 300 )
@ IN NS ns.example.com.
ns IN A {dnssec_lab.AUTH["example"]["ip"]}
www IN A 192.0.2.10
{hosts}
@ IN TXT "dnssec perf experiment zone"
""",
        encoding="ascii",
    )

    (dnssec_lab.ZONES / "com" / "db.com").write_text(
        f"""$ORIGIN com.
$TTL 300
@ IN SOA ns.com. hostmaster.com. (
    {dnssec_lab.SERIAL} 300 300 1200 300 )
@ IN NS ns.com.
ns IN A {dnssec_lab.AUTH["com"]["ip"]}
example.com. IN NS ns.example.com.
ns.example.com. IN A {dnssec_lab.AUTH["example"]["ip"]}
{example_ds}
""",
        encoding="ascii",
    )

    (dnssec_lab.ZONES / "root" / "db.root").write_text(
        f"""$ORIGIN .
$TTL 300
@ IN SOA ns.root. hostmaster.root. (
    {dnssec_lab.SERIAL} 300 300 1200 300 )
@ IN NS ns.root.
ns.root. IN A {dnssec_lab.AUTH["root"]["ip"]}
com. IN NS ns.com.
ns.com. IN A {dnssec_lab.AUTH["com"]["ip"]}
{com_ds}
""",
        encoding="ascii",
    )

    for name in ["root", "com", "example"]:
        dnssec_lab.sign_zone(name, "good")

    start_authorities()


def start_authorities() -> None:
    ensure_loopback_ips([dnssec_lab.AUTH[name]["ip"] for name in ["root", "com", "example"]])
    dnssec_lab.run(["chmod", "-R", "a+rwX", str(dnssec_lab.WORK)], sudo=True)
    for name in ["root", "com", "example"]:
        conf = dnssec_lab.CONF / f"named-{name}.conf"
        conf.write_text(dnssec_lab.named_conf_auth(name), encoding="ascii")
        dnssec_lab.run(["named-checkconf", str(conf)])
        dnssec_lab.log(f"starting authoritative {name} on {dnssec_lab.AUTH[name]['ip']}:53")
        dnssec_lab.run(["named", "-n", "1", "-4", "-c", str(conf)], sudo=True)
    for name in ["root", "com", "example"]:
        wait_for_tcp(dnssec_lab.AUTH[name]["ip"])


def encode_qname(name: str) -> bytes:
    name = name.rstrip(".")
    out = bytearray()
    for label in name.split("."):
        raw = label.encode("ascii")
        if len(raw) > 63:
            raise ValueError(f"label too long: {label}")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def build_query(qid: int, qname: str) -> bytes:
    # Standard recursive query, QTYPE=A, QCLASS=IN.  Clients do not need DO=1
    # for a validating resolver to validate before answering.
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = encode_qname(qname) + struct.pack("!HH", 1, 1)
    return header + question


def response_rcode(packet: bytes) -> int | None:
    if len(packet) < 4:
        return None
    return packet[3] & 0x0F


def write_recursive_resolver_conf(name: str, ip: str, validation: bool) -> Path:
    hints = dnssec_lab.CONF / "root.hints"
    hints.write_text(
        f""". 3600 IN NS ns.root.
ns.root. 3600 IN A {dnssec_lab.AUTH["root"]["ip"]}
""",
        encoding="ascii",
    )
    conf = dnssec_lab.CONF / f"named-{name}.conf"
    trust_anchor = dnssec_lab.root_trust_anchor() if validation else ""
    conf.write_text(
        f"""
options {{
    directory "{dnssec_lab.WORK}";
    listen-on port 53 {{ {ip}; }};
    listen-on-v6 {{ none; }};
    recursion yes;
    dnssec-validation {"yes" if validation else "no"};
    allow-query {{ any; }};
    pid-file "{dnssec_lab.RUN / (name + ".pid")}";
    session-keyfile "{dnssec_lab.RUN / (name + ".session.key")}";
}};

controls {{}};

{trust_anchor}

zone "." IN {{
    type hint;
    file "{hints}";
}};
""",
        encoding="ascii",
    )
    dnssec_lab.run(["named-checkconf", str(conf)])
    return conf


def write_cache_forwarder_conf(name: str, ip: str, forwarders: list[str]) -> Path:
    conf = dnssec_lab.CONF / f"named-{name}.conf"
    forwarder_text = " ".join(f"{item};" for item in forwarders)
    conf.write_text(
        f"""
options {{
    directory "{dnssec_lab.WORK}";
    listen-on port 53 {{ {ip}; }};
    listen-on-v6 {{ none; }};
    recursion yes;
    dnssec-validation no;
    forward only;
    forwarders {{ {forwarder_text} }};
    allow-query {{ any; }};
    pid-file "{dnssec_lab.RUN / (name + ".pid")}";
    session-keyfile "{dnssec_lab.RUN / (name + ".session.key")}";
}};

controls {{}};
""",
        encoding="ascii",
    )
    dnssec_lab.run(["named-checkconf", str(conf)])
    return conf


def ensure_loopback_ips(ips: list[str]) -> None:
    current = dnssec_lab.run(["ip", "-4", "addr", "show", "dev", "lo"], capture=True).stdout
    for ip in ips:
        if f"{ip}/32" not in current and f"{ip}/8" not in current:
            dnssec_lab.run(["ip", "addr", "add", f"{ip}/32", "dev", "lo"], sudo=True, check=False)


def ensure_tiered_resolvers() -> None:
    all_ips = (
        TIER_VALIDATING_BACKENDS
        + TIER_NO_VALIDATE_BACKENDS
        + TIER_VALIDATING_CACHES
        + TIER_NO_VALIDATE_CACHES
    )
    ensure_loopback_ips(all_ips)

    configs: list[Path] = []
    for index, ip in enumerate(TIER_VALIDATING_BACKENDS, start=1):
        configs.append(write_recursive_resolver_conf(f"resolver-v{index}", ip, validation=True))
    for index, ip in enumerate(TIER_NO_VALIDATE_BACKENDS, start=1):
        configs.append(write_recursive_resolver_conf(f"resolver-nv{index}", ip, validation=False))
    for index, ip in enumerate(TIER_VALIDATING_CACHES, start=1):
        configs.append(write_cache_forwarder_conf(f"cache-v{index}", ip, TIER_VALIDATING_BACKENDS))
    for index, ip in enumerate(TIER_NO_VALIDATE_CACHES, start=1):
        configs.append(write_cache_forwarder_conf(f"cache-nv{index}", ip, TIER_NO_VALIDATE_BACKENDS))

    for conf in configs:
        dnssec_lab.run(["named", "-n", "1", "-4", "-c", str(conf)], sudo=True)
    for ip in all_ips:
        wait_for_tcp(ip)


def wait_for_tcp(ip: str) -> None:
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection((ip, PORT), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    raise SystemExit(f"resolver did not start listening on {ip}:{PORT}")


def make_names(mode: str, total: int, records: int) -> list[str]:
    if mode == "hot":
        return ["www.example.com."] * total
    if mode == "positive":
        return [f"host-{i % records}.example.com." for i in range(total)]
    if mode == "nxdomain":
        return [f"miss-{i}-{random.randrange(1_000_000_000)}.example.com." for i in range(total)]
    raise ValueError(f"unknown mode: {mode}")


def warm_resolver(targets: list[str]) -> None:
    for name in ["www.example.com.", "miss-warmup.example.com."]:
        try:
            run_udp_benchmark(targets, [name] * 20, concurrency=4, timeout=1.0)
        except Exception:
            pass


def run_udp_benchmark(
    targets: list[str],
    names: list[str],
    *,
    concurrency: int,
    timeout: float,
) -> dict[str, float | int]:
    sel = selectors.DefaultSelector()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    sel.register(sock, selectors.EVENT_READ)

    total = len(names)
    next_index = 0
    next_qid = 1
    in_flight: dict[int, tuple[float, str]] = {}
    latencies: list[float] = []
    rcode_counts: dict[int, int] = {}
    timed_out = 0
    sent = 0
    target_index = 0
    start = time.perf_counter()

    def send_one() -> None:
        nonlocal next_index, next_qid, sent, target_index
        qname = names[next_index]
        qid = next_qid
        target = targets[target_index % len(targets)]
        target_index += 1
        next_index += 1
        next_qid = 1 if next_qid >= 65535 else next_qid + 1
        now = time.perf_counter()
        sock.sendto(build_query(qid, qname), (target, PORT))
        in_flight[qid] = (now, qname)
        sent += 1

    try:
        while next_index < total and len(in_flight) < concurrency:
            send_one()

        while in_flight or next_index < total:
            now = time.perf_counter()
            expired = [qid for qid, (sent_at, _) in in_flight.items() if now - sent_at > timeout]
            for qid in expired:
                in_flight.pop(qid, None)
                timed_out += 1

            while next_index < total and len(in_flight) < concurrency:
                send_one()

            events = sel.select(timeout=0.01)
            for key, _ in events:
                packet, _addr = key.fileobj.recvfrom(4096)
                if len(packet) < 2:
                    continue
                qid = struct.unpack("!H", packet[:2])[0]
                item = in_flight.pop(qid, None)
                if not item:
                    continue
                sent_at, _qname = item
                latencies.append(time.perf_counter() - sent_at)
                rcode = response_rcode(packet)
                if rcode is not None:
                    rcode_counts[rcode] = rcode_counts.get(rcode, 0) + 1
    finally:
        sel.unregister(sock)
        sock.close()

    elapsed = time.perf_counter() - start
    lat_ms = [x * 1000 for x in latencies]
    lat_ms.sort()
    ok = len(lat_ms)
    p50 = statistics.median(lat_ms) if lat_ms else 0.0
    p95 = lat_ms[int(ok * 0.95) - 1] if ok else 0.0
    p99 = lat_ms[int(ok * 0.99) - 1] if ok else 0.0
    return {
        "sent": sent,
        "received": ok,
        "timeouts": timed_out,
        "elapsed_sec": elapsed,
        "qps": ok / elapsed if elapsed else 0.0,
        "p50_ms": p50,
        "p95_ms": p95,
        "p99_ms": p99,
        "rcode_noerror": rcode_counts.get(0, 0),
        "rcode_nxdomain": rcode_counts.get(3, 0),
        "rcode_servfail": rcode_counts.get(2, 0),
    }


def print_result(label: str, mode: str, result: dict[str, float | int]) -> None:
    print(
        f"{label:18s} mode={mode:8s} "
        f"qps={result['qps']:.1f} "
        f"p50={result['p50_ms']:.3f}ms "
        f"p95={result['p95_ms']:.3f}ms "
        f"p99={result['p99_ms']:.3f}ms "
        f"recv={result['received']}/{result['sent']} "
        f"timeout={result['timeouts']} "
        f"rcode(NOERROR/NXDOMAIN/SERVFAIL)="
        f"{result['rcode_noerror']}/{result['rcode_nxdomain']}/{result['rcode_servfail']}"
    )


def run_experiment(args: argparse.Namespace) -> None:
    setup_perf_zone(args.records)
    ensure_tiered_resolvers()
    validating_targets = TIER_VALIDATING_CACHES
    no_validate_targets = TIER_NO_VALIDATE_CACHES
    print("topology                 2 cache + 2 recursive")
    print("validation=yes caches    ", ", ".join(TIER_VALIDATING_CACHES))
    print("validation=yes resolvers ", ", ".join(TIER_VALIDATING_BACKENDS))
    print("validation=no caches     ", ", ".join(TIER_NO_VALIDATE_CACHES))
    print("validation=no resolvers  ", ", ".join(TIER_NO_VALIDATE_BACKENDS))
    print("queries_per_run          ", args.queries)
    print("concurrency              ", args.concurrency)
    print("positive_records         ", args.records)
    print()

    for targets in [validating_targets, no_validate_targets]:
        warm_resolver(targets)

    for mode in args.mode:
        print(f"[mode] {mode}")
        for label, targets in [("validation=yes", validating_targets), ("validation=no", no_validate_targets)]:
            names = make_names(mode, args.queries, args.records)
            result = run_udp_benchmark(targets, names, concurrency=args.concurrency, timeout=args.timeout)
            print_result(label, mode, result)
        print()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queries", type=int, default=20000)
    parser.add_argument("--concurrency", type=int, default=256)
    parser.add_argument("--records", type=int, default=10000, help="number of positive A records in example.com")
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--mode", choices=["hot", "positive", "nxdomain"], nargs="+", default=["hot", "positive", "nxdomain"])
    args = parser.parse_args(argv)
    run_experiment(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

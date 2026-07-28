from .common import Scenario


def sign_args(ctx, zone_name: str) -> list[str] | None:
    if zone_name == "example":
        return ["-3", "-", "-H", "0", "-A", "-e", ctx.FUTURE_END]
    return None


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name != "example":
        return

    import base64
    from datetime import datetime, timedelta, timezone

    import dns.dnssec
    import dns.name
    import dns.rdata
    import dns.rdataclass
    import dns.rdataset
    import dns.rdatatype
    import dns.zone
    from cryptography.hazmat.primitives.asymmetric import ec

    import dnssec_lab as lab

    path = ctx.signed_zone_path("example")
    origin = dns.name.from_text("example.com.")
    zone = dns.zone.from_file(str(path), origin=origin, relativize=False)

    zsk = next(p for p in lab.key_files("example") if " 256 3 13 " in p.read_text(encoding="ascii"))
    key_text = zsk.read_text(encoding="ascii").split()
    dnskey = dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.DNSKEY,
        " ".join(key_text[key_text.index("DNSKEY") + 1 :]),
    )
    private_text = zsk.with_suffix(".private").read_text(encoding="ascii").splitlines()
    private_b64 = next(line.split(": ", 1)[1] for line in private_text if line.startswith("PrivateKey:"))
    private_key = ec.derive_private_key(int.from_bytes(base64.b64decode(private_b64), "big"), ec.SECP256R1())

    changed = 0
    for owner, node in zone.nodes.items():
        rdataset = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC3)
        if rdataset is None:
            continue
        rdata = next(iter(rdataset))
        if not rdata.flags & 0x01:
            continue

        new_rdata = rdata.replace(flags=rdata.flags & ~0x01)
        new_rdataset = dns.rdataset.from_rdata(rdataset.ttl, new_rdata)
        node.replace_rdataset(new_rdataset)
        try:
            node.delete_rdataset(dns.rdataclass.IN, dns.rdatatype.RRSIG, dns.rdatatype.NSEC3)
        except KeyError:
            pass
        sig = dns.dnssec.sign(
            (owner, new_rdataset),
            private_key,
            origin,
            dnskey,
            inception=lab.dns_time(datetime.now(timezone.utc) - timedelta(hours=1)),
            expiration=lab.FUTURE_END,
            verify=True,
        )
        sigs = node.find_rdataset(dns.rdataclass.IN, dns.rdatatype.RRSIG, covers=dns.rdatatype.NSEC3, create=True)
        sigs.add(sig, ttl=new_rdataset.ttl)
        node.replace_rdataset(sigs)
        changed += 1

    if not changed:
        raise SystemExit("no NSEC3 opt-out records found to mutate")
    zone.to_file(str(path), sorted=True, relativize=False)


scenario = Scenario(
    name="opt-out-flag-not-set",
    description="对 unsigned delegation 使用 NSEC3 opt-out proof，但清除覆盖记录的 opt-out flag。",
    expected_codes=("OPT_OUT_FLAG_NOT_SET",),
    qname="child.example.com.",
    rrtypes="DS",
    extra_example_records=(
        "child.example.com. 300 IN NS ns.child.example.com.",
        "ns.child.example.com. 300 IN A 127.10.0.3",
    ),
    sign_args=sign_args,
    after_sign_zone=after_sign_zone,
    fix_message="fixing missing NSEC3 opt-out flag by regenerating the opt-out NSEC3 chain for unsigned delegations.",
)

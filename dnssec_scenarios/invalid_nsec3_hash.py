from .common import Scenario


def sign_args(ctx, zone_name: str) -> list[str] | None:
    if zone_name == "example":
        return ["-3", "-", "-H", "0", "-e", ctx.FUTURE_END]
    return None


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name != "example":
        return

    import base64
    from datetime import datetime, timedelta, timezone

    import dns.dnssec
    import dns.name
    import dns.rdataclass
    import dns.rdataset
    import dns.rdatatype
    import dns.zone
    from cryptography.hazmat.primitives.asymmetric import ec

    import dnssec_lab as lab

    path = ctx.signed_zone_path("example")
    origin = dns.name.from_text("example.com.")
    owner = dns.name.from_text("ONIB9MGUB9H0RML3CDF5BGRJ59DKJHVK.example.com.")
    zone = dns.zone.from_file(str(path), origin=origin, relativize=False)
    node = zone.get_node(owner)
    rdataset = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC3)
    rdata = next(iter(rdataset))
    new_rdata = rdata.replace(next=b"\x00")
    new_rdataset = dns.rdataset.from_rdata(rdataset.ttl, new_rdata)
    node.replace_rdataset(new_rdataset)
    try:
        node.delete_rdataset(dns.rdataclass.IN, dns.rdatatype.RRSIG, dns.rdatatype.NSEC3)
    except KeyError:
        pass

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
    zone.to_file(str(path), sorted=True, relativize=False)


scenario = Scenario(
    name="invalid-nsec3-hash",
    description="将 NSEC3 next hashed owner name 改成非法长度并重新签名。",
    expected_codes=("INVALID_NSEC3_HASH",),
    qname="absent.example.com.",
    rrtypes="A",
    sign_args=sign_args,
    after_sign_zone=after_sign_zone,
    fix_message="fixing invalid NSEC3 next hash by regenerating the NSEC3 chain and resigning example.com.",
)

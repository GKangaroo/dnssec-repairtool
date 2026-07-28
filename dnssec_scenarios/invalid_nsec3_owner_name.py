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
    old_owner = dns.name.from_text("ONIB9MGUB9H0RML3CDF5BGRJ59DKJHVK.example.com.")
    new_owner = dns.name.from_text("ZZZZ.example.com.")
    zone = dns.zone.from_file(str(path), origin=origin, relativize=False)
    old_node = zone.get_node(old_owner)
    new_node = zone.get_node(new_owner, create=True)
    rdataset = old_node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC3)
    new_node.replace_rdataset(rdataset)
    try:
        old_node.delete_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC3)
        old_node.delete_rdataset(dns.rdataclass.IN, dns.rdatatype.RRSIG, dns.rdatatype.NSEC3)
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
        (new_owner, rdataset),
        private_key,
        origin,
        dnskey,
        inception=lab.dns_time(datetime.now(timezone.utc) - timedelta(hours=1)),
        expiration=lab.FUTURE_END,
        verify=True,
    )
    sigs = dns.rdataset.from_rdata(rdataset.ttl, sig)
    new_node.replace_rdataset(sigs)
    zone.to_file(str(path), sorted=True, relativize=False)


scenario = Scenario(
    name="invalid-nsec3-owner-name",
    description="将 NSEC3 owner name 改成非法 Base32hex label 并重新签名。",
    expected_codes=("INVALID_NSEC3_OWNER_NAME",),
    qname="absent.example.com.",
    rrtypes="A",
    sign_args=sign_args,
    after_sign_zone=after_sign_zone,
    fix_message="fixing invalid NSEC3 owner name by regenerating the NSEC3 chain and resigning example.com.",
)

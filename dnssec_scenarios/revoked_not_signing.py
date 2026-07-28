from .common import Scenario


def before_write(ctx) -> None:
    ctx.revoke_key("example", ksk=False)


def sign_args(ctx, zone_name: str) -> list[str] | None:
    if zone_name != "example":
        return None
    return ["-P", "-e", ctx.FUTURE_END]


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name != "example":
        return

    import dns.dnssec
    import dns.name
    import dns.rdataclass
    import dns.rdatatype
    import dns.rdataset
    import dns.zone

    path = ctx.signed_zone_path("example")
    origin = dns.name.from_text("example.com.")
    zone = dns.zone.from_file(str(path), origin=origin, relativize=False)
    apex = zone.get_node(origin)
    dnskeys = apex.get_rdataset(dns.rdataclass.IN, dns.rdatatype.DNSKEY)
    rrsigs = apex.get_rdataset(dns.rdataclass.IN, dns.rdatatype.RRSIG, dns.rdatatype.DNSKEY)
    revoked_tags = {dns.dnssec.key_id(key) for key in dnskeys if key.flags & 0x80}
    kept = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.RRSIG)
    kept.ttl = rrsigs.ttl
    for sig in rrsigs:
        if sig.key_tag not in revoked_tags:
            kept.add(sig, ttl=rrsigs.ttl)
    apex.replace_rdataset(kept)
    zone.to_file(str(path), sorted=True, relativize=False)


def before_fix(ctx) -> None:
    ctx.reset_keys("example")
    ctx.ensure_keys()


scenario = Scenario(
    name="revoked-not-signing",
    description="在 DNSKEY RRset 中发布设置了 REVOKE bit 的 ZSK，但该 revoked key 不应作为有效签名 key。",
    expected_codes=("REVOKED_NOT_SIGNING",),
    qname="example.com.",
    rrtypes="DNSKEY",
    before_write=before_write,
    sign_args=sign_args,
    after_sign_zone=after_sign_zone,
    before_fix=before_fix,
    fix_message="fixing revoked non-signing ZSK by removing the revoked key and resigning example.com.",
)

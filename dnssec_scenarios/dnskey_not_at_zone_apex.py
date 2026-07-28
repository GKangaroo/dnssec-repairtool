from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.append_dnskey_at_owner(ctx.signed_zone_path("example"), "not-apex.example.com.")


scenario = Scenario(
    name="dnskey-not-at-zone-apex",
    description="在 not-apex.example.com. 发布 DNSKEY RRset，触发 DNSKEY 不在 zone apex 的诊断。",
    expected_codes=("DNSKEY_NOT_AT_ZONE_APEX",),
    qname="not-apex.example.com.",
    rrtypes="DNSKEY",
    after_sign_zone=after_sign_zone,
    fix_message="fixing non-apex DNSKEY by removing the DNSKEY RRset outside the zone apex and resigning example.com.",
)

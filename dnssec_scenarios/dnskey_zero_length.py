from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.mutate_dnskey_public_key(ctx.signed_zone_path("example"), 256, [])


scenario = Scenario(
    name="dnskey-zero-length",
    description="将 ZSK DNSKEY 公钥置空；BIND 下通常退化为非法响应，后续应改用 custom wire responder。",
    expected_codes=("DNSKEY_ZERO_LENGTH",),
    qname="example.com.",
    rrtypes="DNSKEY",
    after_sign_zone=after_sign_zone,
    fix_message="fixing zero-length DNSKEY by restoring the DNSKEY RRset and resigning example.com.",
)

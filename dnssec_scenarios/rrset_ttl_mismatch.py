from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.mutate_www_a_rrset_ttl(ctx.signed_zone_path("example"))


scenario = Scenario(
    name="rrset-ttl-mismatch",
    description="修改 www.example.com. A RRset TTL，使其与 RRSIG TTL 不一致。",
    expected_codes=("RRSET_TTL_MISMATCH",),
    after_sign_zone=after_sign_zone,
    fix_message="fixing RRset TTL that exceeds RRSIG original TTL by resigning example.com.",
)

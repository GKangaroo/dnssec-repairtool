from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.mutate_www_a_rrset_ttl(ctx.signed_zone_path("example"))
        ctx.mutate_www_a_rrsig_record_ttl(ctx.signed_zone_path("example"))


scenario = Scenario(
    name="original-ttl-exceeded-rrset",
    description="修改 www.example.com. A RRset TTL，使其超过 RRSIG original TTL。",
    expected_codes=("ORIGINAL_TTL_EXCEEDED_RRSET", "ORIGINAL_TTL_EXCEEDED_RRSIG"),
    after_sign_zone=after_sign_zone,
    fix_message="fixing RRset TTL that exceeds RRSIG original TTL by resigning example.com.",
)

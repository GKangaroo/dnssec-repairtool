from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.mutate_www_a_rrsig_record_ttl(ctx.signed_zone_path("example"))


scenario = Scenario(
    name="original-ttl-exceeded-rrsig",
    description="修改 www.example.com. 的 RRSIG A 记录 TTL，使其超过 original TTL。",
    expected_codes=("ORIGINAL_TTL_EXCEEDED_RRSIG", "RRSET_TTL_MISMATCH"),
    after_sign_zone=after_sign_zone,
    fix_message="fixing RRSIG record TTL that exceeds original TTL by resigning example.com.",
)

from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.strip_rrsig_a(ctx.signed_zone_path("example"))


scenario = Scenario(
    name="missing-rrsig",
    description="删除 www.example.com. 的 A RRset 签名。",
    expected_codes=("MISSING_RRSIG",),
    after_sign_zone=after_sign_zone,
    fix_message="fixing missing RRSIG by resigning example.com.",
)


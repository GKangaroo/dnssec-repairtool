from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.mutate_rrsig_signature(ctx.signed_zone_path("example"), replacement="AA==")


scenario = Scenario(
    name="rrsig-bad-length-ecdsa256",
    description="将 RRSIG A 签名替换为错误长度；BIND 下通常退化为非法响应，后续应改用 custom wire responder。",
    expected_codes=("RRSIG_BAD_LENGTH_ECDSA256",),
    after_sign_zone=after_sign_zone,
    fix_message="fixing bad-length ECDSA P-256 RRSIG by resigning example.com.",
)


from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.corrupt_rrsig_signature(ctx.signed_zone_path("example"))


scenario = Scenario(
    name="signature-invalid",
    description="翻转 www.example.com. 的 RRSIG A 签名字节。",
    expected_codes=("SIGNATURE_INVALID",),
    after_sign_zone=after_sign_zone,
    fix_message="fixing invalid RRSIG by resigning example.com.",
)


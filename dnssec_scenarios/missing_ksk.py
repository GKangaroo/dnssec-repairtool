from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.strip_dnskey_ksk(ctx.signed_zone_path("example"))


scenario = Scenario(
    name="missing-ksk",
    description="删除子区 apex 的 KSK DNSKEY。",
    expected_codes=("MISSING_SEP_FOR_ALG", "NO_SEP", "SIGNATURE_INVALID"),
    after_sign_zone=after_sign_zone,
    fix_message="fixing missing KSK by restoring DNSKEY RRset and resigning example.com.",
)


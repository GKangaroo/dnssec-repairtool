from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.mutate_dnskey_public_key(ctx.signed_zone_path("example"), 256, ["AA=="])


scenario = Scenario(
    name="dnskey-bad-length-ecdsa256",
    description="将 ECDSA P-256 ZSK DNSKEY 公钥替换为错误长度。",
    expected_codes=("DNSKEY_BAD_LENGTH_ECDSA256", "NO_SEP", "SIGNATURE_INVALID"),
    after_sign_zone=after_sign_zone,
    fix_message="fixing bad-length ECDSA P-256 DNSKEY by restoring the DNSKEY RRset and resigning example.com.",
)


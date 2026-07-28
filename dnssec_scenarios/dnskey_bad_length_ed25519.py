from .common import Scenario


def before_write(ctx) -> None:
    ctx.ensure_algorithm_keys("example", "ED25519")


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.mutate_dnskey_public_key(ctx.signed_zone_path("example"), 256, ["AA=="], algorithm=15)


scenario = Scenario(
    name="dnskey-bad-length-ed25519",
    description="将 Ed25519 ZSK DNSKEY 公钥替换为错误长度。",
    expected_codes=("DNSKEY_BAD_LENGTH_ED25519", "NO_SEP", "SIGNATURE_INVALID"),
    before_write=before_write,
    after_sign_zone=after_sign_zone,
    fix_message="fixing bad-length Ed25519 DNSKEY by restoring the DNSKEY RRset and resigning example.com.",
)

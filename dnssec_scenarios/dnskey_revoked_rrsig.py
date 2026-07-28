from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.mutate_www_a_signed_by_revoked_zsk(ctx.signed_zone_path("example"))


def before_fix(ctx) -> None:
    ctx.reset_keys("example")
    ctx.ensure_keys()


scenario = Scenario(
    name="dnskey-revoked-rrsig",
    description="将 ZSK DNSKEY 标记为 revoked，并用该 revoked ZSK 重签 www.example.com. A。",
    expected_codes=("DNSKEY_REVOKED_RRSIG", "NO_SEP", "SIGNATURE_INVALID"),
    after_sign_zone=after_sign_zone,
    before_fix=before_fix,
    fix_message="fixing revoked ZSK used for signatures by restoring DNSKEY flags and resigning example.com.",
)

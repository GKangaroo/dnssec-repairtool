from .common import Scenario


def before_write(ctx) -> None:
    ctx.revoke_key("example", ksk=True)


def sign_args(ctx, zone_name: str) -> list[str] | None:
    if zone_name != "example":
        return None
    return ["-P", "-e", ctx.FUTURE_END]


def before_fix(ctx) -> None:
    ctx.reset_keys("example")
    ctx.ensure_keys()


scenario = Scenario(
    name="dnskey-revoked-ds",
    description="父区 DS 指向已设置 REVOKE bit 的 KSK。",
    qname="example.com.",
    rrtypes="DNSKEY",
    expected_codes=("DNSKEY_REVOKED_DS",),
    before_write=before_write,
    sign_args=sign_args,
    before_fix=before_fix,
    fix_message="fixing revoked KSK referenced by DS by restoring DNSKEY flags and resigning example.com.",
)

from .common import Scenario


def sign_args(ctx, zone_name: str) -> list[str] | None:
    if zone_name != "example":
        return None
    return ["-P", "-s", ctx.EXPIRED_START, "-e", ctx.EXPIRED_END]


scenario = Scenario(
    name="expired-rrsig",
    description="子区使用已经过期的 RRSIG。",
    expected_codes=("EXPIRATION_IN_PAST", "NO_SEP"),
    sign_args=sign_args,
    fix_message="fixing expired RRSIG by resigning example.com with a future expiration.",
)


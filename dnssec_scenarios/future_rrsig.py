from .common import Scenario


def sign_args(ctx, zone_name: str) -> list[str] | None:
    if zone_name != "example":
        return None
    return ["-P", "-s", ctx.FUTURE_START, "-e", ctx.FUTURE_SIG_END]


scenario = Scenario(
    name="future-rrsig",
    description="子区使用生效时间在未来的 RRSIG。",
    expected_codes=("INCEPTION_IN_FUTURE", "NO_SEP"),
    sign_args=sign_args,
    fix_message="fixing future RRSIG inception by resigning example.com with a current inception.",
)


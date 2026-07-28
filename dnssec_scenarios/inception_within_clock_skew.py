from datetime import datetime, timedelta, timezone

from .common import Scenario


def sign_args(ctx, zone_name: str) -> list[str] | None:
    if zone_name != "example":
        return None
    start = ctx.dns_time(datetime.now(timezone.utc) - timedelta(seconds=60))
    return ["-P", "-s", start, "-e", ctx.FUTURE_END]


scenario = Scenario(
    name="inception-within-clock-skew",
    description="子区 RRSIG inception 距当前时间过近，落入 DNSViz clock skew 警告窗口。",
    expected_codes=("INCEPTION_WITHIN_CLOCK_SKEW",),
    sign_args=sign_args,
    fix_message="fixing near-current RRSIG inception by resigning example.com with a safer inception time.",
)

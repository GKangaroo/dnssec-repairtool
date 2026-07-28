from datetime import datetime, timedelta, timezone

from .common import Scenario


def sign_args(ctx, zone_name: str) -> list[str] | None:
    if zone_name != "example":
        return None
    end = ctx.dns_time(datetime.now(timezone.utc) + timedelta(seconds=60))
    return ["-P", "-e", end]


scenario = Scenario(
    name="expiration-within-clock-skew",
    description="子区 RRSIG expiration 距当前时间过近，落入 DNSViz clock skew 警告窗口。",
    expected_codes=("EXPIRATION_WITHIN_CLOCK_SKEW",),
    example_ttl=30,
    sign_args=sign_args,
    fix_message="fixing near-current RRSIG expiration by resigning example.com with a safer expiration time.",
)

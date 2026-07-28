from datetime import datetime, timedelta, timezone

from .common import Scenario


def sign_args(ctx, zone_name: str) -> list[str] | None:
    if zone_name != "example":
        return None
    return ["-P", "-e", ctx.dns_time(datetime.now(timezone.utc) + timedelta(minutes=10))]


scenario = Scenario(
    name="ttl-beyond-expiration",
    description="设置较长 TTL 和较短签名有效期，使 TTL 超过 RRSIG 过期时间。",
    expected_codes=("TTL_BEYOND_EXPIRATION", "RRSET_TTL_MISMATCH"),
    example_ttl=7200,
    sign_args=sign_args,
    fix_message="fixing TTL beyond RRSIG expiration by resigning example.com with a longer validity window.",
)


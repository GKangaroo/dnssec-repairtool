from .common import Scenario


def sign_args(ctx, zone_name: str) -> list[str] | None:
    if zone_name != "example":
        return None
    return ["-P", "-s", ctx.EXPIRED_START, "-e", ctx.EXPIRED_END]


scenario = Scenario(
    name="realcase-tamu-edu-expired-rrsig",
    description=(
        "从 tamu.edu 2023-01-05 DNSSEC outage 规约复制的真实故障："
        "DNSKEY/RRset RRSIG 已过期，验证解析器返回 Signature Expired/SERVFAIL。"
    ),
    expected_codes=("EXPIRATION_IN_PAST", "NO_SEP"),
    qname="www.example.com.",
    rrtypes="A",
    sign_args=sign_args,
    fix_message="fixing realcase tamu.edu expired RRSIG by resigning the child zone with fresh validity timestamps.",
)

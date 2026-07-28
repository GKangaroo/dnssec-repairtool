from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.corrupt_rrsig_signature(ctx.signed_zone_path("example"))


scenario = Scenario(
    name="realcase-sigfail-ippacket-stream",
    description=(
        "从公开 DNSSEC 失败样本 sigfail.ippacket.stream 规约复制的真实故障："
        "业务 RRset 的 RRSIG 无法被 DNSKEY 验证。"
    ),
    expected_codes=("SIGNATURE_INVALID",),
    qname="www.example.com.",
    rrtypes="A",
    after_sign_zone=after_sign_zone,
    fix_message="fixing realcase sigfail.ippacket.stream by resigning the child zone with valid private keys.",
)

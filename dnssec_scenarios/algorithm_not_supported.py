from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.mutate_zsk_dnskey_algorithm_and_rrsig(
            ctx.signed_zone_path("example"),
            "A",
            "www.example.com.",
            253,
        )


scenario = Scenario(
    name="algorithm-not-supported",
    description="将 RRSIG A 的 algorithm 字段改成 DNSViz 不支持的私有算法编号。",
    expected_codes=("ALGORITHM_NOT_SUPPORTED",),
    after_sign_zone=after_sign_zone,
    fix_message="fixing unsupported RRSIG algorithm by resigning example.com with the default supported algorithm.",
)

from .common import Scenario


def before_write(ctx) -> None:
    ctx.ensure_algorithm_keys("example", "ECDSAP384SHA384")


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.strip_dnskey_rrsig_algorithm(ctx.signed_zone_path("example"), 14)


scenario = Scenario(
    name="missing-rrsig-for-alg-dnskey",
    description="双算法 DNSKEY RRset 中删除算法 14 的 DNSKEY RRSIG。",
    expected_codes=("MISSING_RRSIG_FOR_ALG_DNSKEY",),
    before_write=before_write,
    after_sign_zone=after_sign_zone,
    fix_message="fixing missing DNSKEY RRset signature for one algorithm by resigning example.com.",
)


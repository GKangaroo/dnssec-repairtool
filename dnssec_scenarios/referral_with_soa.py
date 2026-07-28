from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "com":
        ctx.mutate_nsec_bitmap(ctx.signed_zone_path("com"), "example.com.", add=("SOA",), zone_name="com")


scenario = Scenario(
    name="referral-with-soa",
    description="在父区 delegation 的 NSEC bitmap 中错误加入 SOA 类型。",
    expected_codes=("REFERRAL_WITH_SOA",),
    qname="example.com.",
    rrtypes="DS",
    include_example_ds=False,
    after_sign_zone=after_sign_zone,
    fix_message="fixing referral NSEC bitmap by removing the incorrect SOA bit and resigning the parent zone.",
)

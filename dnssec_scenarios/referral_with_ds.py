from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "com":
        ctx.mutate_nsec_bitmap(ctx.signed_zone_path("com"), "example.com.", add=("DS",), zone_name="com")


scenario = Scenario(
    name="referral-with-ds",
    description="在 unsigned delegation 的父区 NSEC bitmap 中错误加入 DS 类型。",
    expected_codes=("REFERRAL_WITH_DS",),
    qname="example.com.",
    rrtypes="DS",
    include_example_ds=False,
    after_sign_zone=after_sign_zone,
    fix_message="fixing referral NSEC bitmap by removing the incorrect DS bit and resigning the parent zone.",
)

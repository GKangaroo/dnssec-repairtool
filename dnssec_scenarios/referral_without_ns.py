from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "com":
        ctx.mutate_nsec_bitmap(ctx.signed_zone_path("com"), "example.com.", remove=("NS",), zone_name="com")


scenario = Scenario(
    name="referral-without-ns",
    description="从父区 delegation 的 NSEC bitmap 中错误移除 NS 类型。",
    expected_codes=("REFERRAL_WITHOUT_NS",),
    qname="example.com.",
    rrtypes="DS",
    include_example_ds=False,
    after_sign_zone=after_sign_zone,
    fix_message="fixing referral NSEC bitmap by restoring the NS bit and resigning the parent zone.",
)

from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.mutate_nsec_bitmap(ctx.signed_zone_path("example"), "example.com.", add=("AAAA",))


scenario = Scenario(
    name="stype-in-bitmap",
    description="在 example.com. 的 NSEC bitmap 中加入不存在的 AAAA 类型。",
    expected_codes=("STYPE_IN_BITMAP",),
    qname="example.com.",
    rrtypes="AAAA",
    after_sign_zone=after_sign_zone,
    fix_message="fixing incorrect NSEC type bitmap by regenerating denial-of-existence records.",
)

from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.mutate_nsec_bitmap(
            ctx.signed_zone_path("example"),
            "example.com.",
            next_name="aaa.example.com.",
        )


scenario = Scenario(
    name="sname-not-covered",
    description="修改 apex NSEC 的 next domain，使其不能覆盖不存在名字 absent.example.com.。",
    expected_codes=("SNAME_NOT_COVERED",),
    qname="absent.example.com.",
    rrtypes="A",
    after_sign_zone=after_sign_zone,
    fix_message="fixing NSEC proof that does not cover the SNAME by regenerating the NSEC chain.",
)

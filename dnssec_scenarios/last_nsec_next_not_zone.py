from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.mutate_nsec_bitmap(
            ctx.signed_zone_path("example"),
            "www.example.com.",
            next_name="ns.example.com.",
        )


scenario = Scenario(
    name="last-nsec-next-not-zone",
    description="将最后一个 NSEC 的 next domain 从 zone apex 改成非 apex 名字。",
    expected_codes=("LAST_NSEC_NEXT_NOT_ZONE",),
    qname="zzz.example.com.",
    rrtypes="A",
    after_sign_zone=after_sign_zone,
    fix_message="fixing invalid final NSEC next domain by regenerating the NSEC chain.",
)

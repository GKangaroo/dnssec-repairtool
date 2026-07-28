from .common import Scenario


def sign_args(ctx, zone_name: str) -> list[str] | None:
    if zone_name == "example":
        return ["-3", "-", "-H", "0", "-e", ctx.FUTURE_END]
    return None


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.mutate_nsec3_bitmap(
            ctx.signed_zone_path("example"),
            "4F3CNT8CU22TNGEC382JJ4GDE4RB47UB.example.com.",
            next_hash="20000000000000000000000000000000",
        )


scenario = Scenario(
    name="wildcard-covered",
    description="在 wildcard 正向答案中篡改 NSEC3 next hash，使 proof 错误覆盖 wildcard 自身。",
    expected_codes=("WILDCARD_COVERED",),
    qname="foo.example.com.",
    rrtypes="A",
    extra_example_records=("*.example.com. 300 IN A 192.0.2.20",),
    sign_args=sign_args,
    after_sign_zone=after_sign_zone,
    fix_message="fixing NSEC3 proof that incorrectly covers an existing wildcard by regenerating the denial-of-existence chain and resigning example.com.",
)

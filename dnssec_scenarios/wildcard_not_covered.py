from .common import Scenario


def sign_args(ctx, zone_name: str) -> list[str] | None:
    if zone_name == "example":
        return ["-3", "-", "-H", "0", "-e", ctx.FUTURE_END]
    return None


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.mutate_nsec3_bitmap(
            ctx.signed_zone_path("example"),
            "ONIB9MGUB9H0RML3CDF5BGRJ59DKJHVK.example.com.",
            next_hash="00000000000000000000000000000000",
        )


scenario = Scenario(
    name="wildcard-not-covered",
    description="修改 NSEC3 next hash，使 NXDOMAIN 证明覆盖 SNAME 但不覆盖对应 wildcard。",
    expected_codes=("WILDCARD_NOT_COVERED",),
    qname="absent.example.com.",
    rrtypes="A",
    sign_args=sign_args,
    after_sign_zone=after_sign_zone,
    fix_message="fixing NSEC3 proof that does not cover the wildcard by regenerating the denial-of-existence chain and resigning example.com.",
)

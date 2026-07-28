from .common import Scenario


def sign_args(ctx, zone_name: str) -> list[str] | None:
    if zone_name == "example":
        return ["-3", "-", "-H", "0", "-e", ctx.FUTURE_END]
    return None


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.mutate_nsec3_bitmap(
            ctx.signed_zone_path("example"),
            "PTJ67J96LVVVBU5K3V6N10B6QMO17275.example.com.",
            next_hash="V0000000000000000000000000000000",
        )


scenario = Scenario(
    name="next-closest-encloser-not-covered",
    description="篡改覆盖 next closest encloser 的 NSEC3 next hash，使其不再覆盖 b.example.com.",
    expected_codes=("NEXT_CLOSEST_ENCLOSER_NOT_COVERED",),
    qname="a.b.example.com.",
    rrtypes="A",
    sign_args=sign_args,
    after_sign_zone=after_sign_zone,
    fix_message="fixing NSEC3 proof that does not cover next closest encloser by regenerating the NSEC3 chain.",
)

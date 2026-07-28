from .common import Scenario


def sign_args(ctx, zone_name: str) -> list[str] | None:
    if zone_name == "example":
        return ["-3", "-", "-H", "0", "-e", ctx.FUTURE_END]
    return None


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.strip_nsec3_owner(
            ctx.signed_zone_path("example"),
            "ONIB9MGUB9H0RML3CDF5BGRJ59DKJHVK.example.com.",
        )


scenario = Scenario(
    name="no-closest-encloser",
    description="删除 NSEC3 proof 中用于证明 closest encloser 的关键 RRset，使 NXDOMAIN 证明无法成立。",
    expected_codes=("NO_CLOSEST_ENCLOSER",),
    qname="absent.example.com.",
    rrtypes="A",
    sign_args=sign_args,
    after_sign_zone=after_sign_zone,
    fix_message="fixing invalid NSEC3 closest-encloser proof by regenerating the denial-of-existence chain and resigning example.com.",
)

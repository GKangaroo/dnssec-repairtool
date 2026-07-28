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
    name="no-nsec3-matching-sname",
    description="删除 example.com. 对应的 NSEC3 RRset，使 NODATA 响应缺少匹配 SNAME 的 NSEC3 证明。",
    expected_codes=("NO_NSEC3_MATCHING_SNAME",),
    qname="example.com.",
    rrtypes="AAAA",
    sign_args=sign_args,
    after_sign_zone=after_sign_zone,
    fix_message="fixing missing matching NSEC3 proof for SNAME by regenerating the denial-of-existence chain and resigning example.com.",
)

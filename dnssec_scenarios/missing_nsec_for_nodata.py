from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.strip_nsec_records(ctx.signed_zone_path("example"))


scenario = Scenario(
    name="missing-nsec-for-nodata",
    description="删除 NSEC 链后查询已有名字 example.com. 的不存在类型 AAAA。",
    expected_codes=("MISSING_NSEC_FOR_NODATA", "MISSING_RRSIG", "MISSING_SEP_FOR_ALG", "NO_SEP"),
    qname="example.com.",
    rrtypes="AAAA",
    after_sign_zone=after_sign_zone,
    fix_message="fixing missing NSEC proof for NODATA by regenerating the denial-of-existence chain.",
)


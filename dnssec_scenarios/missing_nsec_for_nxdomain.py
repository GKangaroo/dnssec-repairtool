from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.strip_nsec_records(ctx.signed_zone_path("example"))


scenario = Scenario(
    name="missing-nsec-for-nxdomain",
    description="删除 NSEC 链后查询不存在名字 absent.example.com.",
    expected_codes=("MISSING_NSEC_FOR_NXDOMAIN", "MISSING_RRSIG", "MISSING_SEP_FOR_ALG", "NO_SEP"),
    qname="absent.example.com.",
    after_sign_zone=after_sign_zone,
    fix_message="fixing missing NSEC proof for NXDOMAIN by regenerating the denial-of-existence chain.",
)


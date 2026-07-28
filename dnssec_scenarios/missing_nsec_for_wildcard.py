from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.strip_nsec_records(ctx.signed_zone_path("example"))


scenario = Scenario(
    name="missing-nsec-for-wildcard",
    description="发布 wildcard 后删除 NSEC 链；当前构造会被 DNSViz 归并为 MISSING_NSEC_FOR_NODATA。",
    expected_codes=("MISSING_NSEC_FOR_WILDCARD",),
    qname="foo.example.com.",
    extra_example_records=("* IN A 192.0.2.53",),
    after_sign_zone=after_sign_zone,
    fix_message="fixing missing NSEC proof for wildcard expansion by regenerating the denial-of-existence chain.",
)


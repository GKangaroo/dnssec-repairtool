from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.mutate_nsec_bitmap(
            ctx.signed_zone_path("example"),
            "example.com.",
            next_name="ns.example.com.",
        )


scenario = Scenario(
    name="no-nsec-matching-sname",
    description="构造 empty-nonterminal NODATA 响应，并篡改 apex NSEC next domain，使其不能作为 SNAME 的匹配证明。",
    expected_codes=("NO_NSEC_MATCHING_SNAME",),
    qname="empty.example.com.",
    rrtypes="AAAA",
    extra_example_records=("leaf.empty.example.com. 300 IN A 192.0.2.30",),
    after_sign_zone=after_sign_zone,
    fix_message="fixing NSEC proof that does not match the SNAME by regenerating the denial-of-existence chain and resigning example.com.",
)

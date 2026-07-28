from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.mutate_rrsig_labels_signed(ctx.signed_zone_path("example"), "www.example.com.", "A", 5)


scenario = Scenario(
    name="rrsig-labels-exceed-owner-labels",
    description="把 www.example.com. 的 RRSIG labels 字段改成过大的值。",
    expected_codes=("RRSIG_LABELS_EXCEED_RRSET_OWNER_LABELS",),
    after_sign_zone=after_sign_zone,
    fix_message="fixing invalid RRSIG label count by resigning example.com.",
)

from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.mutate_www_a_rrsig_signer(ctx.signed_zone_path("example"))


scenario = Scenario(
    name="signer-not-zone",
    description="把 www.example.com. 的 RRSIG A signer name 改成父区 com.",
    expected_codes=("SIGNER_NOT_ZONE",),
    after_sign_zone=after_sign_zone,
    fix_message="fixing out-of-zone signer by resigning example.com.",
)


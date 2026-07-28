from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name != "example":
        return

    path = ctx.signed_zone_path("example")
    ctx.mutate_rrsig_algorithm(path, "A", "www.example.com.", 12)
    ctx.mutate_rrsig_signature(path, replacement="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", algorithm=12)


scenario = Scenario(
    name="rrsig-bad-length-gost",
    description="将 www A 的 RRSIG algorithm 改为 GOST(12)，并替换为错误长度签名。",
    expected_codes=("RRSIG_BAD_LENGTH_GOST",),
    after_sign_zone=after_sign_zone,
    fix_message="fixing bad-length GOST RRSIG by resigning with a supported valid DNSKEY.",
)

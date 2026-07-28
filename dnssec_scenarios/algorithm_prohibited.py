from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.mutate_rrsig_algorithm(ctx.signed_zone_path("example"), "A", "www.example.com.", 1)


scenario = Scenario(
    name="algorithm-prohibited",
    description="将 RRSIG A 的 algorithm 字段改成 RFC8624 禁止的 RSAMD5。",
    expected_codes=("ALGORITHM_PROHIBITED", "ALGORITHM_VALIDATION_PROHIBITED"),
    after_sign_zone=after_sign_zone,
    fix_message="fixing prohibited RRSIG algorithm by resigning example.com with the default ECDSA algorithm.",
)

from .common import Scenario


def before_write(ctx) -> None:
    ctx.ensure_algorithm_keys("example", "ED448")


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.mutate_rrsig_signature(ctx.signed_zone_path("example"), replacement="AA==", algorithm=16)


def before_fix(ctx) -> None:
    ctx.reset_keys("example")
    ctx.ensure_keys()


scenario = Scenario(
    name="rrsig-bad-length-ed448",
    description="将 Ed448 RRSIG A 签名替换为错误长度；普通权威软件可能退化为非法响应。",
    expected_codes=("RRSIG_BAD_LENGTH_ED448",),
    before_write=before_write,
    after_sign_zone=after_sign_zone,
    before_fix=before_fix,
    fix_message="fixing bad-length Ed448 RRSIG by resigning example.com.",
)

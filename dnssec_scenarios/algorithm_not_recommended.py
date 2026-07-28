from .common import Scenario


def before_write(ctx) -> None:
    ctx.ensure_algorithm_keys("example", "RSASHA1")


def before_fix(ctx) -> None:
    ctx.reset_keys("example")
    ctx.ensure_keys()


scenario = Scenario(
    name="algorithm-not-recommended",
    description="使用 RFC8624 不推荐的 RSASHA1 算法签名子区。",
    expected_codes=("ALGORITHM_NOT_RECOMMENDED",),
    before_write=before_write,
    before_fix=before_fix,
    fix_message="fixing not-recommended signing algorithm by replacing RSASHA1 with the default ECDSA signing policy.",
)

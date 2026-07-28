from .common import Scenario


def sign_args(ctx, zone_name: str) -> list[str] | None:
    if zone_name == "example":
        return ["-3", "A1", "-H", "1", "-e", ctx.FUTURE_END]
    return None


scenario = Scenario(
    name="nonzero-nsec3-iteration-count",
    description="使用非 0 NSEC3 iteration 签名 example.com.，触发 RFC 9276 相关错误。",
    expected_codes=("NONZERO_NSEC3_ITERATION_COUNT",),
    qname="absent.example.com.",
    rrtypes="A",
    sign_args=sign_args,
    fix_message="fixing non-zero NSEC3 iteration count by regenerating the denial-of-existence chain with NSEC/NSEC3 iteration 0.",
)

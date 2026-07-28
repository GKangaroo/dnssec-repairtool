from .common import Scenario


def sign_args(ctx, zone_name: str) -> list[str] | None:
    if zone_name == "example":
        return ["-3", "A1", "-H", "0", "-e", ctx.FUTURE_END]
    return None


scenario = Scenario(
    name="nonempty-nsec3-salt",
    description="使用非空 NSEC3 salt 且 iteration 为 0，单独触发 RFC 9276 salt 诊断。",
    expected_codes=("NONEMPTY_NSEC3_SALT",),
    qname="absent.example.com.",
    rrtypes="A",
    sign_args=sign_args,
    fix_message="fixing non-empty NSEC3 salt by regenerating the denial-of-existence chain with an empty salt.",
)

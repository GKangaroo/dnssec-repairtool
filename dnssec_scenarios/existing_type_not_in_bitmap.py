import shutil

from .common import Scenario


EXAMPLE_NS2_IP = "127.10.0.4"


def before_sign(ctx) -> None:
    example_zone = ctx.unsigned_zone_path("example")
    with example_zone.open("a", encoding="ascii") as fh:
        fh.write(f"\n@ IN NS ns2.example.com.\nns2 IN A {EXAMPLE_NS2_IP}\n")

    com_zone = ctx.unsigned_zone_path("com")
    with com_zone.open("a", encoding="ascii") as fh:
        fh.write(f"\nexample.com. IN NS ns2.example.com.\nns2.example.com. IN A {EXAMPLE_NS2_IP}\n")


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name != "example":
        return

    unsigned = ctx.unsigned_zone_path("example")
    primary = ctx.signed_zone_path("example")
    secondary = primary.with_name("db.example.com.ns2.signed")

    unsigned_text = unsigned.read_text(encoding="ascii")
    primary_text = primary.read_text(encoding="ascii")
    secondary_text = "\n".join(
        line for line in unsigned_text.splitlines() if not line.startswith("www IN A ")
    )
    secondary_text += "\nwww IN TXT \"www exists on ns2 but has no A\"\n"
    try:
        unsigned.write_text(secondary_text + "\n", encoding="ascii")
        ctx.sign_zone("example", "good")
        shutil.copyfile(primary, secondary)
    finally:
        unsigned.write_text(unsigned_text, encoding="ascii")
        primary.write_text(primary_text, encoding="ascii")


scenario = Scenario(
    name="existing-type-not-in-bitmap",
    description="两个 example.com. 权威服务器不一致：主权威返回 www A，副权威证明 www 存在但 A 类型不存在。",
    expected_codes=("EXISTING_TYPE_NOT_IN_BITMAP",),
    qname="www.example.com.",
    rrtypes="A",
    before_sign=before_sign,
    after_sign_zone=after_sign_zone,
    fix_message="fixing contradictory type-existence answers by synchronizing the same signed RRsets across all authoritative servers.",
)

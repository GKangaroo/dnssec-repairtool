import shutil

from .common import Scenario


EXAMPLE_NS2_IP = "127.10.0.4"


def before_sign(ctx) -> None:
    example_zone = ctx.unsigned_zone_path("example")
    with example_zone.open("a", encoding="ascii") as fh:
        fh.write(f"\n@ IN NS ns2.example.com.\nns2 IN A {EXAMPLE_NS2_IP}\nempty IN TXT \"exists but has no A\"\n")

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
    secondary_text = "\n".join(line for line in unsigned_text.splitlines() if not line.startswith("empty IN TXT "))
    try:
        unsigned.write_text(secondary_text + "\n", encoding="ascii")
        ctx.sign_zone("example", "good")
        shutil.copyfile(primary, secondary)
    finally:
        unsigned.write_text(unsigned_text, encoding="ascii")
        primary.write_text(primary_text, encoding="ascii")


scenario = Scenario(
    name="sname-covered",
    description="两个 example.com. 权威服务器不一致：主权威证明 empty 存在但无 A，副权威证明 empty 不存在。",
    expected_codes=("SNAME_COVERED",),
    qname="empty.example.com.",
    rrtypes="A",
    before_sign=before_sign,
    after_sign_zone=after_sign_zone,
    fix_message="fixing contradictory SNAME existence/denial answers by synchronizing the same signed zone across all authoritative servers.",
)

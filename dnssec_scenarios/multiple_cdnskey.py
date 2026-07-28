import shutil

from .common import Scenario


EXAMPLE_NS2_IP = "127.10.0.4"


def before_sign(ctx) -> None:
    example_zone = ctx.unsigned_zone_path("example")
    ctx.append_cdnskey(example_zone)
    with example_zone.open("a", encoding="ascii") as fh:
        fh.write(f"\n@ IN NS ns2.example.com.\nns2 IN A {EXAMPLE_NS2_IP}\n")

    com_zone = ctx.unsigned_zone_path("com")
    with com_zone.open("a", encoding="ascii") as fh:
        fh.write(f"\nexample.com. IN NS ns2.example.com.\nns2.example.com. IN A {EXAMPLE_NS2_IP}\n")


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name != "example":
        return
    primary = ctx.signed_zone_path("example")
    secondary = primary.with_name("db.example.com.ns2.signed")
    shutil.copyfile(primary, secondary)
    ctx.replace_apex_rrset(secondary, "CDNSKEY", [ctx.corrupt_cdnskey_from_ksk()])
    ctx.sign_apex_rrset_with_ksk(secondary, "CDNSKEY")


scenario = Scenario(
    name="multiple-cdnskey",
    description="两个 example.com. 权威服务器返回不同 CDNSKEY RRset variants。",
    expected_codes=("MULTIPLE_CDNSKEY",),
    qname="example.com.",
    rrtypes="CDNSKEY",
    before_sign=before_sign,
    after_sign_zone=after_sign_zone,
    fix_message="fixing multiple CDNSKEY variants by synchronizing the same CDNSKEY RRset across all authoritative servers and resigning example.com.",
)

import shutil

from .common import Scenario


EXAMPLE_NS2_IP = "127.10.0.4"


def before_sign(ctx) -> None:
    example_zone = ctx.unsigned_zone_path("example")
    ctx.append_cds(example_zone)
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
    ctx.replace_apex_rrset(secondary, "CDS", [ctx.corrupt_cds_from_ksk()])
    ctx.sign_apex_rrset_with_ksk(secondary, "CDS")


scenario = Scenario(
    name="multiple-cds",
    description="两个 example.com. 权威服务器返回不同 CDS RRset variants。",
    expected_codes=("MULTIPLE_CDS",),
    qname="example.com.",
    rrtypes="CDS",
    before_sign=before_sign,
    after_sign_zone=after_sign_zone,
    fix_message="fixing multiple CDS variants by synchronizing the same CDS RRset across all authoritative servers and resigning example.com.",
)

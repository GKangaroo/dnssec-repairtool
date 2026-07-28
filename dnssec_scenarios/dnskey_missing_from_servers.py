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
    primary = ctx.signed_zone_path("example")
    secondary = primary.with_name("db.example.com.ns2.signed")
    shutil.copyfile(primary, secondary)
    ctx.strip_dnskey_ksk(secondary)
    ctx.sign_apex_rrset_with_zsk(secondary, "DNSKEY")


scenario = Scenario(
    name="dnskey-missing-from-servers",
    description="配置两个 example.com. 权威服务器，其中第二个权威缺少 KSK DNSKEY。",
    expected_codes=("DNSKEY_MISSING_FROM_SERVERS",),
    qname="example.com.",
    rrtypes="DNSKEY",
    before_sign=before_sign,
    after_sign_zone=after_sign_zone,
    fix_message="fixing DNSKEY mismatch across authoritative servers by publishing the same DNSKEY RRset on every server and resigning example.com.",
)

from .common import Scenario


def before_sign(ctx) -> None:
    ctx.append_cds(ctx.unsigned_zone_path("example"))


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name == "example":
        ctx.sign_apex_rrset_with_zsk(ctx.signed_zone_path("example"), "CDS")


scenario = Scenario(
    name="cds-signer-invalid",
    description="用未被父区 DS 认可的 ZSK 签署 CDS RRset。",
    expected_codes=("CDS_SIGNER_INVALID",),
    qname="example.com.",
    rrtypes="CDS",
    before_sign=before_sign,
    after_sign_zone=after_sign_zone,
    fix_message="fixing invalid CDS signer by resigning CDS with a key represented in both DNSKEY and DS.",
)

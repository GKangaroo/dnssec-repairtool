from .common import Scenario


# Public evidence, observed from dnssec-failed.org:
# dnssec-failed.org. DS 42069 13 2
#   62726F6B656E20636861696E206F662074727573742073656E642068656C7021
#
# The digest bytes decode to "broken chain of trust send help!".  In the local
# lab we map the same broken DS rdata onto the currently configured child zone
# so the parent publishes a DS that cannot authenticate any child KSK.
DNSSEC_FAILED_ORG_DS_RDATA = (
    "42069 13 2 "
    "62726F6B656E20636861696E206F662074727573742073656E642068656C7021"
)


def before_sign(ctx) -> None:
    import dnssec_lab

    parent = ctx.unsigned_zone_path("com")
    child_zone = dnssec_lab.AUTH["example"]["zone"]
    ctx.strip_ds_records(parent, child_zone)
    with parent.open("a", encoding="ascii") as fh:
        fh.write(f"{child_zone} IN DS {DNSSEC_FAILED_ORG_DS_RDATA}\n")


scenario = Scenario(
    name="realcase-dnssec-failed-org",
    description=(
        "从公网 dnssec-failed.org 规约复制的真实故障：父区发布 DS=42069/13/2，"
        "但子区没有对应 KSK，导致 DS/DNSKEY 信任链断裂。"
    ),
    expected_codes=("MISSING_SEP_FOR_ALG", "NO_SEP"),
    qname="www.example.com.",
    rrtypes="A",
    before_sign=before_sign,
    fix_message="fixing realcase dnssec-failed.org by replacing orphan parent DS with DS generated from current child KSK.",
)

from .common import Scenario


# Cloudflare's .al incident write-up describes a failed rollover where the
# parent DS still pointed at the previous DNSKEY id 26319 while the child zone
# no longer served that key.  This local case maps that stale-parent-DS state
# onto the currently configured child zone.
STALE_AL_DS_RDATA = (
    "26319 13 2 "
    "A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1"
)


def before_sign(ctx) -> None:
    import dnssec_lab

    parent = ctx.unsigned_zone_path("com")
    child_zone = dnssec_lab.AUTH["example"]["zone"]
    ctx.strip_ds_records(parent, child_zone)
    with parent.open("a", encoding="ascii") as fh:
        fh.write(f"{child_zone} IN DS {STALE_AL_DS_RDATA}\n")


scenario = Scenario(
    name="realcase-al-stale-ds-rollover",
    description=(
        "从 .al TLD DNSSEC rollover 事故规约复制的真实故障：父区 DS 仍指向旧 key tag，"
        "但子区已经不再发布对应 DNSKEY。"
    ),
    expected_codes=("MISSING_SEP_FOR_ALG", "NO_SEP"),
    qname="www.example.com.",
    rrtypes="A",
    before_sign=before_sign,
    fix_message="fixing realcase .al stale DS rollover by replacing the parent DS with one generated from the current child KSK.",
)

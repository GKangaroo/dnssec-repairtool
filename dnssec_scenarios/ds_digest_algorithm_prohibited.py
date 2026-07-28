from .common import Scenario


def before_sign(ctx) -> None:
    ctx.append_ds_with_digest(ctx.unsigned_zone_path("com"), "example", "SHA1")


scenario = Scenario(
    name="ds-digest-algorithm-prohibited",
    description="父区为子区同时发布 SHA-256 DS 和 RFC8624 禁止的 SHA-1 DS。",
    expected_codes=("DIGEST_ALGORITHM_PROHIBITED", "DS_DIGEST_ALGORITHM_IGNORED"),
    qname="example.com.",
    rrtypes="DS",
    before_sign=before_sign,
    fix_message="fixing prohibited DS digest algorithm by removing SHA-1 DS and resigning com.",
)

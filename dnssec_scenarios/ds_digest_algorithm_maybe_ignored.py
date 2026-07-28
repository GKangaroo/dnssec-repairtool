from .common import Scenario


def before_sign(ctx) -> None:
    path = ctx.unsigned_zone_path("com")
    ctx.strip_ds_records(path, "example.com.")
    ctx.append_ds_with_digest(path, "example", "SHA1")
    ctx.append_ds_with_digest(path, "example", "SHA384")


scenario = Scenario(
    name="ds-digest-algorithm-maybe-ignored",
    description="父区为子区同时发布 SHA-1 DS 和 SHA-384 DS，使 SHA-1 DS 可能被忽略。",
    expected_codes=("DS_DIGEST_ALGORITHM_MAYBE_IGNORED", "DIGEST_ALGORITHM_PROHIBITED"),
    qname="example.com.",
    rrtypes="DS",
    before_sign=before_sign,
    fix_message="fixing maybe-ignored SHA-1 DS by publishing only the default SHA-256 DS and resigning com.",
)

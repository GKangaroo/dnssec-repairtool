from .common import Scenario


def before_sign(ctx) -> None:
    path = ctx.unsigned_zone_path("com")
    ctx.strip_ds_records(path, "example.com.")
    ctx.append_ds_with_digest_type(path, "example", 99)


scenario = Scenario(
    name="digest-algorithm-not-supported",
    description="父区发布 digest type 不被 DNSViz 支持的 DS 记录。",
    expected_codes=("DIGEST_ALGORITHM_NOT_SUPPORTED",),
    qname="example.com.",
    rrtypes="DS",
    before_sign=before_sign,
    fix_message="fixing unsupported DS digest algorithm by publishing a supported SHA-256 DS and resigning com.",
)

from .common import Scenario


def before_sign(ctx) -> None:
    ctx.append_inconsistent_cdnskey(ctx.unsigned_zone_path("example"))


scenario = Scenario(
    name="cdnskey-inconsistent-with-ds",
    description="在子区 apex 发布与父区 DS 不一致的 CDNSKEY 信任链自动化信号。",
    expected_codes=("CDNSKEY_INCONSISTENT_WITH_DS",),
    qname="example.com.",
    rrtypes="CDNSKEY",
    before_sign=before_sign,
    fix_message="fixing inconsistent CDNSKEY by removing the incorrect child CDNSKEY signal and resigning example.com.",
)

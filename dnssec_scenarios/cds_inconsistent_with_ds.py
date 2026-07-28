from .common import Scenario


def before_sign(ctx) -> None:
    ctx.append_inconsistent_cds(ctx.unsigned_zone_path("example"))


scenario = Scenario(
    name="cds-inconsistent-with-ds",
    description="在子区 apex 发布与父区 DS 不一致的 CDS 信任链自动化信号。",
    expected_codes=("CDS_INCONSISTENT_WITH_DS",),
    qname="example.com.",
    rrtypes="CDS",
    before_sign=before_sign,
    fix_message="fixing inconsistent CDS by removing the incorrect child CDS signal and resigning example.com.",
)

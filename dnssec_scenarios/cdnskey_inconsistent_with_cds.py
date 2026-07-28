from .common import Scenario


def before_sign(ctx) -> None:
    path = ctx.unsigned_zone_path("example")
    ctx.append_inconsistent_cds(path)
    ctx.append_cdnskey(path)


scenario = Scenario(
    name="cdnskey-inconsistent-with-cds",
    description="在子区 apex 同时发布彼此不一致的 CDS 与 CDNSKEY 自动化信号。",
    expected_codes=("CDNSKEY_INCONSISTENT_WITH_CDS",),
    qname="example.com.",
    rrtypes="CDS,CDNSKEY",
    before_sign=before_sign,
    fix_message="fixing inconsistent CDS/CDNSKEY by removing incorrect child automation signals and resigning example.com.",
)

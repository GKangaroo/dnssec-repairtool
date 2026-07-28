from .common import Scenario


def before_sign(ctx) -> None:
    with ctx.unsigned_zone_path("example").open("a", encoding="ascii") as fh:
        fh.write("\nexample.com. IN CDS 0 0 0 00\n")
        fh.write("example.com. IN CDS 1 0 0 00\n")


scenario = Scenario(
    name="cds-delete-multiple-records",
    description="在 CDS 删除信号 RRset 中同时发布多条 algorithm 0 记录。",
    expected_codes=("CDS_DELETE_MULTIPLE_RECORDS",),
    qname="example.com.",
    rrtypes="CDS",
    before_sign=before_sign,
    fix_message="fixing multiple CDS delete records by removing malformed automation signals and resigning example.com.",
)

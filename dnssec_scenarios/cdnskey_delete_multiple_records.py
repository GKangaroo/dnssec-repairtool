from .common import Scenario


def before_sign(ctx) -> None:
    with ctx.unsigned_zone_path("example").open("a", encoding="ascii") as fh:
        fh.write("\nexample.com. IN CDNSKEY 0 3 0 AA==\n")
        fh.write("example.com. IN CDNSKEY 1 3 0 AA==\n")


scenario = Scenario(
    name="cdnskey-delete-multiple-records",
    description="在 CDNSKEY 删除信号 RRset 中同时发布多条 algorithm 0 记录。",
    expected_codes=("CDNSKEY_DELETE_MULTIPLE_RECORDS",),
    qname="example.com.",
    rrtypes="CDNSKEY",
    before_sign=before_sign,
    fix_message="fixing multiple CDNSKEY delete records by removing malformed automation signals and resigning example.com.",
)

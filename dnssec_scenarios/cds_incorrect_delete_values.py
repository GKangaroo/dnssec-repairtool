from .common import Scenario


def before_sign(ctx) -> None:
    with ctx.unsigned_zone_path("example").open("a", encoding="ascii") as fh:
        fh.write("\nexample.com. IN CDS 1 0 0 00\n")


scenario = Scenario(
    name="cds-incorrect-delete-values",
    description="发布 algorithm 0 但字段值不符合 RFC 8078 删除信号要求的 CDS 记录。",
    expected_codes=("CDS_INCORRECT_DELETE_VALUES",),
    qname="example.com.",
    rrtypes="CDS",
    before_sign=before_sign,
    fix_message="fixing malformed CDS delete signal by removing it and resigning example.com.",
)

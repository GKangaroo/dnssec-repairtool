from .common import Scenario


def before_sign(ctx) -> None:
    with ctx.unsigned_zone_path("example").open("a", encoding="ascii") as fh:
        fh.write("\nexample.com. IN CDNSKEY 1 3 0 AA==\n")


scenario = Scenario(
    name="cdnskey-incorrect-delete-values",
    description="发布 algorithm 0 但字段值不符合 RFC 8078 删除信号要求的 CDNSKEY 记录。",
    expected_codes=("CDNSKEY_INCORRECT_DELETE_VALUES",),
    qname="example.com.",
    rrtypes="CDNSKEY",
    before_sign=before_sign,
    fix_message="fixing malformed CDNSKEY delete signal by removing it and resigning example.com.",
)

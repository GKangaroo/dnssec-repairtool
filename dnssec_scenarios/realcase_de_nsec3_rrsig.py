from .common import Scenario


NSEC3_OWNER = "ONIB9MGUB9H0RML3CDF5BGRJ59DKJHVK.example.com."


def sign_args(ctx, zone_name: str) -> list[str] | None:
    if zone_name == "example":
        return ["-3", "-", "-H", "0", "-e", ctx.FUTURE_END]
    return None


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name != "example":
        return

    import dnssec_lab as lab

    lab.corrupt_rrsig_signature(
        ctx.signed_zone_path("example"),
        rrtype="NSEC3",
        owner=NSEC3_OWNER,
    )


scenario = Scenario(
    name="realcase-de-nsec3-rrsig",
    description=(
        "从 .de 事故规约复制的真实故障：NSEC3 否定证明 RRset 的 RRSIG 畸形/无效，"
        "导致落入该 hash 覆盖范围的查询验证失败。"
    ),
    expected_codes=("SIGNATURE_INVALID",),
    qname="absent.example.com.",
    rrtypes="A",
    sign_args=sign_args,
    after_sign_zone=after_sign_zone,
    fix_message="fixing realcase .de NSEC3 RRSIG failure by regenerating NSEC3 proofs and resigning the affected zone.",
)

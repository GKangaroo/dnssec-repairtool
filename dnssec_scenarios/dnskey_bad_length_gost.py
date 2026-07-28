from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name != "example":
        return

    path = ctx.signed_zone_path("example")
    text = path.read_text(encoding="ascii")
    text = text.replace("DNSKEY\t256 3 13", "DNSKEY\t256 3 12", 1)
    path.write_text(text, encoding="ascii")
    ctx.mutate_dnskey_public_key(path, 256, ["AA=="], algorithm=12)


scenario = Scenario(
    name="dnskey-bad-length-gost",
    description="将 ZSK DNSKEY algorithm 改为 GOST(12)，并替换为错误长度公钥。",
    expected_codes=("DNSKEY_BAD_LENGTH_GOST",),
    after_sign_zone=after_sign_zone,
    fix_message="fixing bad-length GOST DNSKEY by replacing it with a supported valid DNSKEY and resigning example.com.",
)

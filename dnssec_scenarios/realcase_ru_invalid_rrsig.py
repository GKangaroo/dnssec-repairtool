import base64
import re

from .common import Scenario


def after_sign_zone(ctx, zone_name: str) -> None:
    if zone_name != "com":
        return

    import dnssec_lab as lab

    path = ctx.signed_zone_path("com")
    lines = path.read_text(encoding="ascii").splitlines()
    replacement = base64.b64encode(b"\x01" * 64).decode("ascii")
    for index, line in enumerate(lines):
        if "RRSIG" in line and "SOA" in line:
            end = index + 1
            while end < len(lines) and ")" not in lines[end]:
                end += 1
            block = lines[index : end + 1]
            metadata = next(
                item
                for item in block[1:]
                if re.search(r"\d{14}\s+\d{14}\s+\d+\s+\S+", item)
            )
            lines[index : end + 1] = [
                "; ERROR: INVALID RRSIG - signature bytes replaced with repeated 0x01",
                block[0],
                metadata,
                f"                                        {replacement} )",
            ]
            break
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


scenario = Scenario(
    name="realcase-ru-invalid-rrsig",
    description=(
        "复现 2024 年 .ru 事故的已公开机理：将区域 SOA 的 RRSIG 替换为"
        "醒目的重复字节签名，验证解析器因 RRSIG 校验失败返回 SERVFAIL。"
    ),
    expected_codes=("SIGNATURE_INVALID",),
    qname="com.",
    rrtypes="SOA",
    after_sign_zone=after_sign_zone,
    fix_message="fixing the .ru incident model by regenerating valid signatures for the affected parent zone.",
)

#!/usr/bin/env python3
import json
import re
from collections import defaultdict
from pathlib import Path


LAB_ROOT = Path(__file__).resolve().parents[1]
COVERAGE_JSON = LAB_ROOT / "docs" / "dnsviz_error_coverage.json"
RECORDS = LAB_ROOT / "docs" / "error-records"
INDEX = RECORDS / "README.md"

SCENARIO_COMMANDS = {
    "algorithm-not-recommended": "python3 dnssec_lab.py demo algorithm-not-recommended",
    "algorithm-not-supported": "python3 dnssec_lab.py demo algorithm-not-supported",
    "algorithm-prohibited": "python3 dnssec_lab.py demo algorithm-prohibited",
    "bad-ds": "python3 dnssec_lab.py demo bad-ds",
    "expired-rrsig": "python3 dnssec_lab.py demo expired-rrsig",
    "future-rrsig": "python3 dnssec_lab.py demo future-rrsig",
    "expiration-within-clock-skew": "python3 dnssec_lab.py demo expiration-within-clock-skew",
    "inception-within-clock-skew": "python3 dnssec_lab.py demo inception-within-clock-skew",
    "missing-rrsig": "python3 dnssec_lab.py demo missing-rrsig",
    "signature-invalid": "python3 dnssec_lab.py demo signature-invalid",
    "missing-ksk": "python3 dnssec_lab.py demo missing-ksk",
    "dnskey-bad-length-ecdsa256": "python3 dnssec_lab.py demo dnskey-bad-length-ecdsa256",
    "dnskey-bad-length-ecdsa384": "python3 dnssec_lab.py demo dnskey-bad-length-ecdsa384",
    "dnskey-bad-length-ed25519": "python3 dnssec_lab.py demo dnskey-bad-length-ed25519",
    "dnskey-bad-length-ed448": "python3 dnssec_lab.py demo dnskey-bad-length-ed448",
    "dnskey-revoked-rrsig": "python3 dnssec_lab.py demo dnskey-revoked-rrsig",
    "dnskey-revoked-ds": "python3 dnssec_lab.py demo dnskey-revoked-ds",
    "missing-rrsig-for-alg-dnskey": "python3 dnssec_lab.py demo missing-rrsig-for-alg-dnskey",
    "missing-nsec-for-nxdomain": "python3 dnssec_lab.py demo missing-nsec-for-nxdomain",
    "missing-nsec-for-nodata": "python3 dnssec_lab.py demo missing-nsec-for-nodata",
    "stype-in-bitmap": "python3 dnssec_lab.py demo stype-in-bitmap",
    "referral-with-ds": "python3 dnssec_lab.py demo referral-with-ds",
    "referral-with-soa": "python3 dnssec_lab.py demo referral-with-soa",
    "referral-without-ns": "python3 dnssec_lab.py demo referral-without-ns",
    "last-nsec-next-not-zone": "python3 dnssec_lab.py demo last-nsec-next-not-zone",
    "sname-not-covered": "python3 dnssec_lab.py demo sname-not-covered",
    "nonzero-nsec3-iteration-count": "python3 dnssec_lab.py demo nonzero-nsec3-iteration-count",
    "no-closest-encloser": "python3 dnssec_lab.py demo no-closest-encloser",
    "no-nsec3-matching-sname": "python3 dnssec_lab.py demo no-nsec3-matching-sname",
    "no-nsec-matching-sname": "python3 dnssec_lab.py demo no-nsec-matching-sname",
    "no-trust-anchor-signing": "python3 dnssec_lab.py demo no-trust-anchor-signing",
    "existing-type-not-in-bitmap": "python3 dnssec_lab.py demo existing-type-not-in-bitmap",
    "wildcard-not-covered": "python3 dnssec_lab.py demo wildcard-not-covered",
    "wildcard-covered": "python3 dnssec_lab.py demo wildcard-covered",
    "rrsig-labels-exceed-owner-labels": "python3 dnssec_lab.py demo rrsig-labels-exceed-owner-labels",
    "rrset-ttl-mismatch": "python3 dnssec_lab.py demo rrset-ttl-mismatch",
    "original-ttl-exceeded-rrset": "python3 dnssec_lab.py demo original-ttl-exceeded-rrset",
    "original-ttl-exceeded-rrsig": "python3 dnssec_lab.py demo original-ttl-exceeded-rrsig",
    "signer-not-zone": "python3 dnssec_lab.py demo signer-not-zone",
    "ttl-beyond-expiration": "python3 dnssec_lab.py demo ttl-beyond-expiration",
    "cds-inconsistent-with-ds": "python3 dnssec_lab.py demo cds-inconsistent-with-ds",
    "cdnskey-inconsistent-with-ds": "python3 dnssec_lab.py demo cdnskey-inconsistent-with-ds",
    "cdnskey-inconsistent-with-cds": "python3 dnssec_lab.py demo cdnskey-inconsistent-with-cds",
    "cds-signer-invalid": "python3 dnssec_lab.py demo cds-signer-invalid",
    "cdnskey-signer-invalid": "python3 dnssec_lab.py demo cdnskey-signer-invalid",
    "cname-loop": "python3 dnssec_lab.py demo cname-loop",
    "digest-algorithm-not-supported": "python3 dnssec_lab.py demo digest-algorithm-not-supported",
    "ds-digest-algorithm-prohibited": "python3 dnssec_lab.py demo ds-digest-algorithm-prohibited",
    "ds-digest-algorithm-maybe-ignored": "python3 dnssec_lab.py demo ds-digest-algorithm-maybe-ignored",
}

SCENARIO_FIXES = {
    "algorithm-not-recommended": "移除 RSASHA1 等不推荐签名算法，使用当前推荐的 ECDSA/EdDSA 签名策略重新生成密钥、重签子区并复测。",
    "algorithm-not-supported": "移除不支持的私有 DNSSEC 算法，使用当前支持的 ECDSA/EdDSA 签名策略重新生成密钥、重签子区并复测。",
    "algorithm-prohibited": "移除 RFC8624 禁止的签名算法，使用当前推荐算法重新签名相关 RRset，并复测验证链。",
    "bad-ds": "重新生成正确的子区 DS，发布到父区，重签父区，重启 BIND 后复测。",
    "expired-rrsig": "重新签名子区，让 RRSIG 的过期时间位于未来，重启 BIND 后复测。",
    "future-rrsig": "重新签名子区，让 RRSIG 的生效时间回到当前可验证时间范围内，重启 BIND 后复测。",
    "expiration-within-clock-skew": "重新签名子区，使 RRSIG expiration 远离当前时间的 clock skew 风险窗口。",
    "inception-within-clock-skew": "重新签名子区，使 RRSIG inception 早于当前时间足够长，避开 clock skew 风险窗口。",
    "missing-rrsig": "重新签名子区，恢复缺失的 RRSIG，重启 BIND 后复测。",
    "signature-invalid": "重新签名子区，替换损坏的 RRSIG，重启 BIND 后复测。",
    "missing-ksk": "恢复或发布有效的 KSK DNSKEY，确保 DS 与 KSK 对齐，重签子区，重启 BIND 后复测。",
    "dnskey-bad-length-ecdsa256": "生成正确长度的 ECDSA P-256 DNSKEY，恢复 DNSKEY RRset，重签子区并复测。",
    "dnskey-bad-length-ecdsa384": "生成正确长度的 ECDSA P-384 DNSKEY，恢复 DNSKEY RRset，重签子区并复测。",
    "dnskey-bad-length-ed25519": "生成正确长度的 Ed25519 DNSKEY，恢复 DNSKEY RRset，重签子区并复测。",
    "dnskey-bad-length-ed448": "生成正确长度的 Ed448 DNSKEY，恢复 DNSKEY RRset，重签子区并复测。",
    "dnskey-revoked-rrsig": "生成新的有效 ZSK，替换 revoked ZSK，重签子区并复测。",
    "dnskey-revoked-ds": "生成新的有效 KSK 和对应 DS，将新 DS 发布到父区；等待旧 DS TTL 过期后移除 revoked KSK，并重签子区。",
    "missing-rrsig-for-alg-dnskey": "恢复缺失算法对应的 DNSKEY RRset 签名，重签子区并复测。",
    "missing-nsec-for-nxdomain": "重新生成 NSEC/NSEC3 denial-of-existence 链，重签子区并复测。",
    "missing-nsec-for-nodata": "重新生成 NSEC/NSEC3 denial-of-existence 链，重签子区并复测。",
    "stype-in-bitmap": "重新生成正确的 NSEC type bitmap 并重签子区。",
    "referral-with-ds": "修正父区 delegation NSEC bitmap，移除错误 DS bit 并重签父区。",
    "referral-with-soa": "修正父区 delegation NSEC bitmap，移除错误 SOA bit 并重签父区。",
    "referral-without-ns": "修正父区 delegation NSEC bitmap，恢复 NS bit 并重签父区。",
    "last-nsec-next-not-zone": "重新生成正确的 NSEC 链，使最后一个 NSEC 的 next domain 指回 zone apex。",
    "sname-not-covered": "重新生成正确的 NSEC 链，使 NXDOMAIN 证明覆盖查询名。",
    "nonzero-nsec3-iteration-count": "使用 NSEC 或重新以 NSEC3 iteration 0、空 salt 重签子区并复测。",
    "no-closest-encloser": "重新生成完整 NSEC3 denial-of-existence 链，确保 closest encloser proof 完整，并重签子区。",
    "no-nsec3-matching-sname": "重新生成完整 NSEC3 denial-of-existence 链，确保 NODATA 响应包含匹配 SNAME 的 NSEC3 证明，并重签子区。",
    "no-nsec-matching-sname": "重新生成完整 NSEC denial-of-existence 链，确保 empty-nonterminal 的 NODATA 响应包含匹配 SNAME 的 NSEC 证明，并重签子区。",
    "no-trust-anchor-signing": "修复 DNSViz/验证器的 trust anchor 输入，指向已发布且自签的 KSK 后复测。",
    "existing-type-not-in-bitmap": "重新生成完整 NSEC3 bitmap，确保实际存在的 RR type 被正确列入，并重签子区。",
    "wildcard-not-covered": "重新生成完整 NSEC3 denial-of-existence 链，确保 NXDOMAIN 响应同时覆盖 SNAME 与 wildcard，并重签子区。",
    "wildcard-covered": "重新生成完整 NSEC3 denial-of-existence 链，确保 wildcard 正向答案不会附带覆盖 wildcard 自身的否认证明，并重签子区。",
    "rrsig-labels-exceed-owner-labels": "重新签名子区，恢复 RRSIG labels 字段与 RRset owner label 数量一致。",
    "rrset-ttl-mismatch": "重新签名子区并恢复一致的 RRset/RRSIG TTL，重启 BIND 后复测。",
    "original-ttl-exceeded-rrset": "重新签名子区并恢复 RRset TTL 不超过 RRSIG original TTL，重启 BIND 后复测。",
    "original-ttl-exceeded-rrsig": "重新签名子区并恢复 RRSIG TTL 不超过 original TTL，重启 BIND 后复测。",
    "signer-not-zone": "重新签名子区，恢复 RRSIG signer name 为当前 zone apex，重启 BIND 后复测。",
    "ttl-beyond-expiration": "降低 zone/record TTL 或延长签名有效期，然后重新签名子区，重启 BIND 后复测。",
    "cds-inconsistent-with-ds": "移除错误 CDS 自动化信号，或重新发布与父区 DS 一致的 CDS，然后重签子区并复测。",
    "cdnskey-inconsistent-with-ds": "移除错误 CDNSKEY 自动化信号，或重新发布可派生出父区 DS 的 CDNSKEY，然后重签子区并复测。",
    "cdnskey-inconsistent-with-cds": "移除彼此不一致的 CDS/CDNSKEY 自动化信号，或重新发布能互相派生验证的一致记录，然后重签子区并复测。",
    "cds-signer-invalid": "使用当前 DNSKEY 和父区 DS 均认可的 KSK 重新签署 CDS RRset，删除 ZSK 或未授权 key 产生的 CDS 签名并复测。",
    "cdnskey-signer-invalid": "使用当前 DNSKEY 和父区 DS 均认可的 KSK 重新签署 CDNSKEY RRset，删除 ZSK 或未授权 key 产生的 CDNSKEY 签名并复测。",
    "cname-loop": "移除循环 CNAME，改成最终指向地址记录或非循环别名链，重签子区并复测。",
    "digest-algorithm-not-supported": "移除不支持的 DS digest type，发布支持的 SHA-256 DS，重签父区并复测。",
    "ds-digest-algorithm-prohibited": "移除 RFC8624 禁止的 SHA-1 DS，仅保留支持的 SHA-256 DS，重签父区并复测。",
    "ds-digest-algorithm-maybe-ignored": "移除可能被忽略的 SHA-1 DS，恢复默认 SHA-256 DS，重签父区并复测。",
}

SCENARIO_CODES = {
    "algorithm-not-recommended": ["ALGORITHM_NOT_RECOMMENDED"],
    "algorithm-not-supported": ["ALGORITHM_NOT_SUPPORTED", "MISSING_RRSIG_FOR_ALG_DNSKEY", "MISSING_RRSIG_FOR_ALG_DS", "NO_SEP", "SIGNATURE_INVALID"],
    "algorithm-prohibited": ["ALGORITHM_PROHIBITED", "ALGORITHM_VALIDATION_PROHIBITED"],
    "bad-ds": ["DIGEST_INVALID", "NO_SEP"],
    "expired-rrsig": ["EXPIRATION_IN_PAST", "NO_SEP"],
    "future-rrsig": ["INCEPTION_IN_FUTURE", "NO_SEP"],
    "expiration-within-clock-skew": ["EXPIRATION_WITHIN_CLOCK_SKEW"],
    "inception-within-clock-skew": ["INCEPTION_WITHIN_CLOCK_SKEW"],
    "missing-rrsig": ["MISSING_RRSIG"],
    "signature-invalid": ["SIGNATURE_INVALID"],
    "missing-ksk": ["MISSING_SEP_FOR_ALG", "NO_SEP", "SIGNATURE_INVALID"],
    "dnskey-bad-length-ecdsa256": ["DNSKEY_BAD_LENGTH_ECDSA256", "NO_SEP", "SIGNATURE_INVALID"],
    "dnskey-bad-length-ecdsa384": ["DNSKEY_BAD_LENGTH_ECDSA384", "NO_SEP", "SIGNATURE_INVALID"],
    "dnskey-bad-length-ed25519": ["DNSKEY_BAD_LENGTH_ED25519", "NO_SEP", "SIGNATURE_INVALID"],
    "dnskey-bad-length-ed448": ["DNSKEY_BAD_LENGTH_ED448", "NO_SEP", "SIGNATURE_INVALID"],
    "dnskey-revoked-rrsig": ["DNSKEY_REVOKED_RRSIG", "NO_SEP", "SIGNATURE_INVALID"],
    "dnskey-revoked-ds": ["DNSKEY_REVOKED_DS", "NO_SEP"],
    "missing-rrsig-for-alg-dnskey": ["MISSING_RRSIG_FOR_ALG_DNSKEY"],
    "missing-nsec-for-nxdomain": ["MISSING_NSEC_FOR_NXDOMAIN", "MISSING_RRSIG", "MISSING_SEP_FOR_ALG", "NO_SEP"],
    "missing-nsec-for-nodata": ["MISSING_NSEC_FOR_NODATA", "MISSING_RRSIG", "MISSING_SEP_FOR_ALG", "NO_SEP"],
    "stype-in-bitmap": ["STYPE_IN_BITMAP"],
    "referral-with-ds": ["REFERRAL_WITH_DS"],
    "referral-with-soa": ["REFERRAL_WITH_SOA"],
    "referral-without-ns": ["REFERRAL_WITHOUT_NS"],
    "last-nsec-next-not-zone": ["LAST_NSEC_NEXT_NOT_ZONE"],
    "sname-not-covered": ["SNAME_NOT_COVERED"],
    "nonzero-nsec3-iteration-count": ["NONZERO_NSEC3_ITERATION_COUNT", "NONEMPTY_NSEC3_SALT"],
    "no-closest-encloser": ["NO_CLOSEST_ENCLOSER", "NONZERO_NSEC3_ITERATION_COUNT", "NONEMPTY_NSEC3_SALT"],
    "no-nsec3-matching-sname": ["NO_NSEC3_MATCHING_SNAME", "NONZERO_NSEC3_ITERATION_COUNT", "NONEMPTY_NSEC3_SALT"],
    "no-nsec-matching-sname": ["NO_NSEC_MATCHING_SNAME"],
    "no-trust-anchor-signing": ["NO_TRUST_ANCHOR_SIGNING"],
    "existing-type-not-in-bitmap": ["EXISTING_TYPE_NOT_IN_BITMAP", "NONZERO_NSEC3_ITERATION_COUNT", "NONEMPTY_NSEC3_SALT"],
    "wildcard-not-covered": ["WILDCARD_NOT_COVERED", "NONZERO_NSEC3_ITERATION_COUNT", "NONEMPTY_NSEC3_SALT"],
    "wildcard-covered": ["WILDCARD_COVERED", "NONZERO_NSEC3_ITERATION_COUNT", "NONEMPTY_NSEC3_SALT"],
    "rrsig-labels-exceed-owner-labels": ["RRSIG_LABELS_EXCEED_RRSET_OWNER_LABELS"],
    "rrset-ttl-mismatch": ["RRSET_TTL_MISMATCH"],
    "original-ttl-exceeded-rrset": ["ORIGINAL_TTL_EXCEEDED"],
    "original-ttl-exceeded-rrsig": ["ORIGINAL_TTL_EXCEEDED", "RRSET_TTL_MISMATCH"],
    "signer-not-zone": ["SIGNER_NOT_ZONE"],
    "ttl-beyond-expiration": ["TTL_BEYOND_EXPIRATION", "RRSET_TTL_MISMATCH"],
    "cds-inconsistent-with-ds": ["CDS_INCONSISTENT_WITH_DS", "NO_SEP"],
    "cdnskey-inconsistent-with-ds": ["CDNSKEY_INCONSISTENT_WITH_DS", "MISSING_SEP_FOR_ALG", "NO_SEP"],
    "cdnskey-inconsistent-with-cds": ["CDNSKEY_INCONSISTENT_WITH_CDS", "CDS_INCONSISTENT_WITH_DS", "NO_SEP"],
    "cds-signer-invalid": ["CDS_SIGNER_INVALID"],
    "cdnskey-signer-invalid": ["CDNSKEY_SIGNER_INVALID"],
    "cname-loop": ["CNAME_LOOP", "INVALID_RCODE"],
    "digest-algorithm-not-supported": ["DIGEST_ALGORITHM_NOT_SUPPORTED"],
    "ds-digest-algorithm-prohibited": ["DIGEST_ALGORITHM_PROHIBITED", "DS_DIGEST_ALGORITHM_IGNORED"],
    "ds-digest-algorithm-maybe-ignored": ["DIGEST_ALGORITHM_PROHIBITED", "DS_DIGEST_ALGORITHM_IGNORED", "DS_DIGEST_ALGORITHM_MAYBE_IGNORED"],
}


def slug(code: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", code.lower()).strip("-")


def scenario_names(value: str):
    names = []
    for candidate in SCENARIO_COMMANDS:
        if candidate in value:
            names.append(candidate)
    return names


def record_text(row):
    scenarios = scenario_names(row.get("scenario", ""))
    primary = scenarios[0] if scenarios else ""
    command = SCENARIO_COMMANDS.get(primary, "")
    fix = SCENARIO_FIXES.get(primary, "")
    expected = SCENARIO_CODES.get(primary, [row["code"]] if row["status"] == "done" else [])

    lines = [
        f"# {row['code']}",
        "",
        "## 元信息",
        "",
        f"- DNSViz 类名：`{row['class']}`",
        f"- 错误类别：`{row['category']}`",
        f"- 当前状态：`{row['status']}`",
        f"- 复现方法：`{row['repro_method']}`",
        f"- 复现场景：`{row.get('scenario') or ''}`",
        "",
        "## 中文说明",
        "",
        "待补充该错误的中文机制说明。错误码和 DNSViz 原始描述可在覆盖矩阵 JSON 中追溯。",
        "",
        "## 复现方法",
        "",
    ]
    if command:
        lines += [
            "命令：",
            "",
            "```bash",
            command,
            "```",
            "",
            "预期 DNSViz 错误码：",
            "",
            "```text",
            ", ".join(expected),
            "```",
        ]
    else:
        lines += [
            "尚未实现自动复现。",
            "",
            f"计划使用的复现框架：`{row['repro_method']}`",
        ]
    lines += [
        "",
        "## 修复方式",
        "",
        fix or "尚未实现自动修复。",
        "",
        "## 验证方式",
        "",
    ]
    if command:
        lines += [
            "修复后，DNSViz 错误码应为空，并且递归验证器应返回带 `ad` 标志的 `NOERROR`：",
            "",
            "```bash",
            "dig @127.10.0.53 www.example.com. A +dnssec +multi",
            "```",
        ]
    else:
        lines.append("尚未实现。")
    lines += [
        "",
        "## 备注",
        "",
        "- 实现具体复现场景后，需要同步更新本文件。",
        "",
    ]
    return "\n".join(lines)


def main():
    rows = json.loads(COVERAGE_JSON.read_text())
    RECORDS.mkdir(exist_ok=True)
    for row in rows:
        (RECORDS / f"{slug(row['code'])}.md").write_text(record_text(row), encoding="utf-8")

    by_category = defaultdict(list)
    by_method = defaultdict(list)
    by_status = defaultdict(list)
    for row in rows:
        by_category[row["category"]].append(row)
        by_method[row["repro_method"]].append(row)
        by_status[row["status"]].append(row)

    lines = [
        "# DNSViz 错误记录",
        "",
        f"记录总数：`{len(rows)}`",
        "",
        "## 状态统计",
        "",
        "| 状态 | 数量 |",
        "|---|---:|",
    ]
    for key in sorted(by_status):
        lines.append(f"| `{key}` | {len(by_status[key])} |")

    lines += ["", "## 复现方法统计", "", "| 复现方法 | 数量 |", "|---|---:|"]
    for key in sorted(by_method):
        lines.append(f"| `{key}` | {len(by_method[key])} |")

    lines += ["", "## 按类别索引", ""]
    for category in sorted(by_category):
        lines += [f"### {category}", ""]
        for row in sorted(by_category[category], key=lambda r: r["code"]):
            path = f"{slug(row['code'])}.md"
            scenario = row.get("scenario") or ""
            lines.append(
                f"- [`{row['code']}`]({path}) - `{row['status']}` / `{row['repro_method']}`"
                + (f" / `{scenario}`" if scenario else "")
            )
        lines.append("")

    INDEX.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {len(rows)} records to {RECORDS}")
    print(f"wrote {INDEX}")


if __name__ == "__main__":
    main()

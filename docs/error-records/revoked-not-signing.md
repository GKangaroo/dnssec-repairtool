# REVOKED_NOT_SIGNING

## 元信息

- DNSViz 类名：`RevokedNotSigning`
- 错误类别：`DNSKEYError`
- 当前状态：`done`
- 复现方法：`existing-lab`
- 复现场景：`dnskey-revoked-rrsig`

## 中文说明

待补充该错误的中文机制说明。错误码和 DNSViz 原始描述可在覆盖矩阵 JSON 中追溯。

## 复现方法

命令：

```bash
python3 dnssec_lab.py demo dnskey-revoked-rrsig
```

预期 DNSViz 错误码：

```text
DNSKEY_REVOKED_RRSIG, NO_SEP, SIGNATURE_INVALID
```

## 修复方式

生成新的有效 ZSK，替换 revoked ZSK，重签子区并复测。

## 验证方式

修复后，DNSViz 错误码应为空，并且递归验证器应返回带 `ad` 标志的 `NOERROR`：

```bash
dig @127.10.0.53 www.example.com. A +dnssec +multi
```

## 备注

- 实现具体复现场景后，需要同步更新本文件。

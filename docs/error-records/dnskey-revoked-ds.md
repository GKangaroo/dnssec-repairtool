# DNSKEY_REVOKED_DS

## 元信息

- DNSViz 类名：`DNSKEYRevokedDS`
- 错误类别：`DSError`
- 当前状态：`done`
- 复现方法：`existing-lab`
- 复现场景：`dnskey-revoked-ds`

## 中文说明

待补充该错误的中文机制说明。错误码和 DNSViz 原始描述可在覆盖矩阵 JSON 中追溯。

## 复现方法

命令：

```bash
python3 dnssec_lab.py demo dnskey-revoked-ds
```

预期 DNSViz 错误码：

```text
DNSKEY_REVOKED_DS, NO_SEP
```

## 修复方式

生成新的有效 KSK 和对应 DS，将新 DS 发布到父区；等待旧 DS TTL 过期后移除 revoked KSK，并重签子区。

## 验证方式

修复后，DNSViz 错误码应为空，并且递归验证器应返回带 `ad` 标志的 `NOERROR`：

```bash
dig @127.10.0.53 www.example.com. A +dnssec +multi
```

## 备注

- 实现具体复现场景后，需要同步更新本文件。

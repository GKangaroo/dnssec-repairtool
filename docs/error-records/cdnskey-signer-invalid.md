# CDNSKEY_SIGNER_INVALID

## 元信息

- DNSViz 类名：`CDNSKEYSignerInvalid`
- 错误类别：`CDNSKEYCDSError`
- 当前状态：`done`
- 复现方法：`existing-lab`
- 复现场景：`cdnskey-signer-invalid`

## 中文说明

待补充该错误的中文机制说明。错误码和 DNSViz 原始描述可在覆盖矩阵 JSON 中追溯。

## 复现方法

命令：

```bash
python3 dnssec_lab.py demo cdnskey-signer-invalid
```

预期 DNSViz 错误码：

```text
CDNSKEY_SIGNER_INVALID
```

## 修复方式

使用当前 DNSKEY 和父区 DS 均认可的 KSK 重新签署 CDNSKEY RRset，删除 ZSK 或未授权 key 产生的 CDNSKEY 签名并复测。

## 验证方式

修复后，DNSViz 错误码应为空，并且递归验证器应返回带 `ad` 标志的 `NOERROR`：

```bash
dig @127.10.0.53 www.example.com. A +dnssec +multi
```

## 备注

- 实现具体复现场景后，需要同步更新本文件。

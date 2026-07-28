# CDS_INCONSISTENT_WITH_DS

## 元信息

- DNSViz 类名：`CDSInconsistentWithDS`
- 错误类别：`CDNSKEYCDSError`
- 当前状态：`done`
- 复现方法：`existing-lab`
- 复现场景：`cds-inconsistent-with-ds`

## 中文说明

待补充该错误的中文机制说明。错误码和 DNSViz 原始描述可在覆盖矩阵 JSON 中追溯。

## 复现方法

命令：

```bash
python3 dnssec_lab.py demo cds-inconsistent-with-ds
```

预期 DNSViz 错误码：

```text
CDS_INCONSISTENT_WITH_DS, NO_SEP
```

## 修复方式

移除错误 CDS 自动化信号，或重新发布与父区 DS 一致的 CDS，然后重签子区并复测。

## 验证方式

修复后，DNSViz 错误码应为空，并且递归验证器应返回带 `ad` 标志的 `NOERROR`：

```bash
dig @127.10.0.53 www.example.com. A +dnssec +multi
```

## 备注

- 实现具体复现场景后，需要同步更新本文件。

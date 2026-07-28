# NO_NSEC_MATCHING_SNAME

## 元信息

- DNSViz 类名：`NoNSECMatchingSname`
- 错误类别：`NSECError`
- 当前状态：`done`
- 复现方法：`existing-lab`
- 复现场景：`no-nsec-matching-sname`

## 中文说明

待补充该错误的中文机制说明。错误码和 DNSViz 原始描述可在覆盖矩阵 JSON 中追溯。

## 复现方法

命令：

```bash
python3 dnssec_lab.py demo no-nsec-matching-sname
```

预期 DNSViz 错误码：

```text
NO_NSEC_MATCHING_SNAME
```

## 修复方式

重新生成完整 NSEC denial-of-existence 链，确保 empty-nonterminal 的 NODATA 响应包含匹配 SNAME 的 NSEC 证明，并重签子区。

## 验证方式

修复后，DNSViz 错误码应为空，并且递归验证器应返回带 `ad` 标志的 `NOERROR`：

```bash
dig @127.10.0.53 www.example.com. A +dnssec +multi
```

## 备注

- 实现具体复现场景后，需要同步更新本文件。

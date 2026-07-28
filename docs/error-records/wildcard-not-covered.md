# WILDCARD_NOT_COVERED

## 元信息

- DNSViz 类名：`WildcardNotCovered`
- 错误类别：`NSECError`
- 当前状态：`done`
- 复现方法：`existing-lab`
- 复现场景：`wildcard-not-covered`

## 中文说明

待补充该错误的中文机制说明。错误码和 DNSViz 原始描述可在覆盖矩阵 JSON 中追溯。

## 复现方法

命令：

```bash
python3 dnssec_lab.py demo wildcard-not-covered
```

预期 DNSViz 错误码：

```text
WILDCARD_NOT_COVERED, NONZERO_NSEC3_ITERATION_COUNT, NONEMPTY_NSEC3_SALT
```

## 修复方式

重新生成完整 NSEC3 denial-of-existence 链，确保 NXDOMAIN 响应同时覆盖 SNAME 与 wildcard，并重签子区。

## 验证方式

修复后，DNSViz 错误码应为空，并且递归验证器应返回带 `ad` 标志的 `NOERROR`：

```bash
dig @127.10.0.53 www.example.com. A +dnssec +multi
```

## 备注

- 实现具体复现场景后，需要同步更新本文件。

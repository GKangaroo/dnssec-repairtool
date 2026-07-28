# CNAME_LOOP

## 元信息

- DNSViz 类名：`CNAMELoop`
- 错误类别：`ZoneDataError`
- 当前状态：`done`
- 复现方法：`existing-lab`
- 复现场景：`cname-loop`

## 中文说明

待补充该错误的中文机制说明。错误码和 DNSViz 原始描述可在覆盖矩阵 JSON 中追溯。

## 复现方法

命令：

```bash
python3 dnssec_lab.py demo cname-loop
```

预期 DNSViz 错误码：

```text
CNAME_LOOP, INVALID_RCODE
```

## 修复方式

移除循环 CNAME，改成最终指向地址记录或非循环别名链，重签子区并复测。

## 验证方式

修复后，DNSViz 错误码应为空，并且递归验证器应返回带 `ad` 标志的 `NOERROR`：

```bash
dig @127.10.0.53 www.example.com. A +dnssec +multi
```

## 备注

- 实现具体复现场景后，需要同步更新本文件。

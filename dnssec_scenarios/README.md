# DNSSEC 错误场景

这个目录把每个 DNSViz/DFixer 错误复现场景拆成独立文件。

阅读方式：

1. 先看具体错误文件，例如 `bad_ds.py`、`signature_invalid.py`。
2. 每个文件只描述该错误如何注入、期望错误码、修复说明。
3. 公共场景接口在 `common.py`。
4. 场景注册表在 `registry.py`，`dnssec_lab.py` 会从这里读取可运行场景。

一个场景文件通常只有这些字段：

```python
scenario = Scenario(
    name="signature-invalid",
    description="翻转 www.example.com. 的 RRSIG A 签名字节。",
    expected_codes=("SIGNATURE_INVALID",),
    after_sign_zone=after_sign_zone,
    fix_message="fixing invalid RRSIG by resigning example.com.",
)
```

如果要新增一种错误，优先新建一个文件，而不是继续往 `dnssec_lab.py` 里加 `if scenario == ...`。


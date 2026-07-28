# DNSSEC 验证性能实验报告

## 实验目的

在更接近现实的 DNS 解析架构下，比较后端递归解析器开启 DNSSEC 验证与关闭 DNSSEC 验证时的用户侧吞吐和延迟差异。

## 实验设计

本实验使用本地私有 DNS 层级：

```text
. -> com. -> example.com.
```

其中 `example.com.` 为已签名 DNSSEC zone，父区 `com.` 发布 `example.com.` 的 DS，后端递归解析器可从本地 root trust anchor 完成验证。

实验只保留真实分层拓扑：

```text
用户流量
  -> 2 台前端 cache forwarder
  -> 2 台后端 recursive resolver
  -> 权威服务器
```

具体地址：

```text
validation=yes:
  cache:    127.10.0.51, 127.10.0.52
  resolver: 127.10.0.61, 127.10.0.62

validation=no:
  cache:    127.10.0.55, 127.10.0.56
  resolver: 127.10.0.63, 127.10.0.64
```

两组使用相同权威服务器、相同 zone 数据、相同查询负载，唯一核心差异是后端 recursive resolver 是否开启 DNSSEC 验证。前端 cache 均为 forwarder，不做 DNSSEC 验证。

压测命令：

```bash
python3 tools/dnssec_perf_experiment.py --records 10000 --queries 50000 --concurrency 256
```

参数含义：

```text
records:     example.com. 内生成 10000 条不同 A 记录
queries:     每轮 50000 次查询
concurrency: UDP 并发 256
```

## 查询模式

```text
hot:       重复查询 www.example.com.，主要测前端热缓存路径
positive:  轮询查询 host-0.example.com. 到 host-9999.example.com.，主要测大量真实记录路径
nxdomain:  随机查询不存在名称，主要测否定回答/NSEC 路径
```

## 实验结果

### 热缓存路径

```text
validation=yes  qps=48395.8  p50=5.275ms  p95=5.405ms  p99=5.492ms
validation=no   qps=48223.4  p50=5.301ms  p95=5.376ms  p99=5.431ms
```

开启 DNSSEC 验证后，热缓存 QPS 基本无下降：

```text
(48223.4 - 48395.8) / 48223.4 = -0.4%
```

这说明在前端 cache 已经吸收热点请求时，后端 resolver 的 DNSSEC 验证成本不会体现在每一次用户查询上。

### 大量真实记录路径

```text
validation=yes  qps=29165.0  p50=1.952ms  p95=11.592ms  p99=45.460ms
validation=no   qps=32104.3  p50=2.459ms  p95=13.312ms  p99=36.672ms
```

开启 DNSSEC 验证后，真实记录 QPS 下降约：

```text
(32104.3 - 29165.0) / 32104.3 = 9.2%
```

这说明在前端 cache 存在的架构中，后端 DNSSEC 验证成本会被缓存层稀释，但在大量不同真实记录查询下仍然可观测。

### 随机 NXDOMAIN 路径

```text
validation=yes  qps=14952.6  p50=5.449ms  p95=9.881ms   p99=17.465ms
validation=no   qps=18669.2  p50=4.481ms  p95=10.810ms  p99=14.191ms
```

在该分层 forwarder 拓扑下，开启 DNSSEC 验证后随机 NXDOMAIN QPS 下降约：

```text
(18669.2 - 14952.6) / 18669.2 = 19.9%
```

原因是前端 cache forwarder 本身不做 DNSSEC 验证，随机 NXDOMAIN 查询仍会穿透到后端 resolver，分层转发路径和后端验证都会影响结果。

## 结论

在 2 cache + 2 resolver 架构中：

```text
热缓存重复查询：开启 DNSSEC 验证几乎无吞吐损失。
大量不同真实记录查询：开启 DNSSEC 验证的 QPS 约下降 9.2%。
大量随机不存在域名：本实验中开启 DNSSEC 验证的 QPS 约下降 19.9%。
```

因此，不能简单说“DNSSEC 一定让解析器变慢多少”。性能影响取决于查询分布和验证位置：

```text
热门缓存命中多：损耗较小。
大量不同真实记录冷查询：后端验证开销会体现出来，但前端 cache 会稀释用户侧影响。
大量随机不存在域名：前端非验证 forwarder cache 会削弱 validating resolver 的 aggressive negative caching 收益。
```

当前实验给出的主结论是：**在 2 缓存 + 2 解析的常见架构下，DNSSEC 验证对真实正向查询的用户侧吞吐影响约为 10% 量级。**

## 局限性

本实验是本地分层拓扑模拟，不等价于公网生产环境：

```text
使用单机 BIND 和本地 loopback 网络，2 cache + 2 resolver 也是同机多进程模拟。
权威服务器也在本机，网络 RTT 极低。
使用 Python UDP 压测器，不是 dnsperf/resperf。
zone 使用实验性 ECDSAP256SHA256 签名。
没有采集 CPU、内存、上下游查询量、cache hit ratio。
没有模拟多机部署、真实公网 RTT、真实用户地域分布和缓存生命周期。
```

生产级实验应进一步使用 `dnsperf` / `resperf`、真实查询日志回放、多核递归器配置、独立权威服务器和 CPU 利用率采样。

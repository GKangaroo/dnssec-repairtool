# DNSSEC Auto Deploy & Repair Lab

中文 | [English](README.en.md)

这是一个面向 BIND9 和 PowerDNS 的 DNSSEC 本地实验工具。它会抓取现网域名的解析链记录，并在本地创建可控的 `root -> parent -> child` 权威环境，用于 DNSSEC 部署、错误修复和 demo 演示。

本地环境会保留源域名形状。例如 `dnssec-failed.org.` 会生成 parent zone `org.` 和 child zone `dnssec-failed.org.`；`foo.bar.example.org.` 会生成 parent zone `bar.example.org.` 和 child zone `foo.bar.example.org.`。工具不会把现网域名统一改写成固定测试域名。

## 核心功能

1. 爬取某个现网域名的解析链资源记录，并尝试在本地创建虚拟环境，部署 DNSSEC，并输出 BIND9/PowerDNS 的配置文件。
2. 爬取某个现网域名的解析链资源记录，并尝试在本地创建虚拟环境，为其修复 DNSSEC 部署错误，并输出 BIND9/PowerDNS 的配置文件。
3. 提供 BIND9/PowerDNS 的 DNSSEC 典型错误 demo 演示。

## 运行环境

推荐系统：Debian 12 / Ubuntu 22.04+。本工具会启动本地 53 端口服务并配置 loopback IP，建议在开发机、虚拟机或容器中运行。`demo`、`realcase-demo`、`repair-realcase` 会在运行结束后自动清理本地 DNS 服务。

安装系统依赖：

```bash
sudo apt-get update
sudo apt-get install -y \
  bind9 bind9-utils bind9-dnsutils dnsutils dnsviz \
  graphviz iproute2 libgraphviz-dev \
  pdns-server pdns-backend-bind \
  python3 python3-pip python3-pygraphviz python3-venv procps
```

安装 Python 依赖：

```bash
python3 -m pip install --break-system-packages \
  faker pandas publicsuffixlist requests tldextract tqdm
```

可选：如果你希望使用本地新版 DNSViz 源码，可以把 `dnsviz/` 放在本项目的上一级目录。没有这个源码目录时，工具会使用系统安装的 `dnsviz` 命令。核心部署、修复计划和修复执行都由本项目代码实现，不依赖外部 DFixer 仓库。

## 常用命令

### 1. 现网解析链记录 + 本地 DNSSEC 部署

BIND9：

```bash
python3 dnssec_repair_engine.py deploy-realcase \
  --backend bind9 \
  --domain example.org
```

PowerDNS：

```bash
python3 dnssec_repair_engine.py deploy-realcase \
  --backend powerdns \
  --domain example.org
```

输出中会包含 `config_bundle`，配置包目录形如：

```text
realcase-live/example.org/deploy/bind9-config/
realcase-live/example.org/deploy/powerdns-config/
```

### 2. 现网 DNSSEC 错误 + 本地规约修复

BIND9：

```bash
python3 dnssec_lab.py repair-realcase \
  --domain dnssec-failed.org
```

PowerDNS：

```bash
python3 dnssec_lab.py repair-realcase \
  --domain dnssec-failed.org \
  --backend powerdns
```

输出目录形如：

```text
realcase-live/dnssec-failed.org/bind9-config/
realcase-live/dnssec-failed.org/powerdns-config/
```

当前内置真实案例映射：

```text
dnssec-failed.org        -> realcase-dnssec-failed-org
sigfail.ippacket.stream -> realcase-sigfail-ippacket-stream
al                       -> realcase-al-stale-ds-rollover
tamu.edu                 -> realcase-tamu-edu-expired-rrsig
```

多层级域名也会保留原始层级。例如：

```bash
python3 dnssec_lab.py realcase-demo realcase-dnssec-failed-org \
  --domain foo.bar.example.org \
  --backend bind9
```

会生成：

```text
child zone  = foo.bar.example.org.
parent zone = bar.example.org.
```

### 3. 典型 DNSSEC 错误 demo

BIND9：

```bash
python3 dnssec_lab.py demo bad-ds
```

PowerDNS：

```bash
python3 powerdns_lab.py demo bad-ds
```

可用场景在 `dnssec_scenarios/` 中定义，例如 `bad-ds`、`expired-rrsig`、`signature-invalid`、`missing-rrsig`。

## 输出文件

真实案例输出位于 `realcase-live/<domain>/`。以 `dnssec-failed.org` 为例：

```text
realcase-live/dnssec-failed.org/
├── dnssec-failed.org.live.probe.json
├── dnssec-failed.org.live.grok.json
├── bind9-config/
└── powerdns-config/
```

顶层 `live.*.json` 是现网 DNSViz 观测结果：

- `*.live.probe.json`：DNSViz 原始 probe 数据。
- `*.live.grok.json`：DNSViz 归纳后的诊断摘要。

BIND9 配置包：

```text
bind9-config/
├── named-conf/
├── zones/
├── dnsviz-output/
└── README.txt
```

PowerDNS 配置包：

```text
powerdns-config/
├── powerdns-conf/
├── resolver-conf/
├── powerdns-dnssec-db/
├── zones/
├── dnsviz-output/
└── README.txt
```

关键目录含义：

- `zones/`：修复后的 zone 文件。`db.*` 是未签名 zone，`db.*.signed` 是 DNSSEC 签名后的 zone。
- `dnsviz-output/`：修复前后 DNSViz 摘要和 `repair-plan.json`。
- `named-conf/`：BIND9 权威和 resolver 配置。
- `powerdns-conf/`：PowerDNS 权威配置。
- `powerdns-dnssec-db/`：PowerDNS DNSSEC 元数据 sqlite 文件。

`work/` 和 `realcase-live/` 都是运行产物，可以删除后重新生成。

## 测试

```bash
python3 -m unittest discover -s tests
```

## 上传 GitHub 时保留

建议上传整个 `dnssec-local-lab/` 目录，但不要提交运行产物。`.gitignore` 已默认排除：

```text
work/
realcase-live/
artifacts/
__pycache__/
*.pyc
*.log
*.pid
```

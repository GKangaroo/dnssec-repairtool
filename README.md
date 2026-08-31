# DNSSEC Auto Deploy & Repair Lab

中文 | [English](README.en.md)

这是一个面向 BIND9 和 PowerDNS 的 DNSSEC 本地实验工具。它会抓取现网域名的解析链记录，并在本地创建可控的 `root -> parent -> child` 权威环境，用于 DNSSEC 部署、错误修复和 demo 演示。

本地环境会保留源域名形状。例如 `dnssec-failed.org.` 会生成 parent zone `org.` 和 child zone `dnssec-failed.org.`；`foo.bar.example.org.` 会生成 parent zone `bar.example.org.` 和 child zone `foo.bar.example.org.`。工具不会把现网域名统一改写成固定测试域名。

## 核心功能

1. 爬取某个现网域名的解析链资源记录，并尝试在本地创建虚拟环境，部署 DNSSEC，并输出 BIND9/PowerDNS 的配置文件。
2. 爬取某个现网域名的解析链资源记录，并尝试在本地创建虚拟环境，为其修复 DNSSEC 部署错误，并输出 BIND9/PowerDNS 的配置文件。
3. 提供 BIND9/PowerDNS 的 DNSSEC 典型错误 demo 演示。

其中，现网未部署 DNSSEC 的域名可以直接走第 1 条工作流：工具会读取现网解析链和业务记录，在本地生成带 DNSSEC 的 BIND9/PowerDNS 配置包。从修复视角看，这也可以理解为把“DNSSEC 缺失”规约为本地部署修复。

## 大模型与项目级 Skill

仓库内置了供大模型读取的项目级 Skill：

```text
.trae/skills/dnssec-deploy-repair/
├── SKILL.md
└── references/
    ├── workflows.md
    └── error-codes.md
```

在支持项目级 Skill 的大模型客户端中打开本仓库后，可以要求大模型使用
`dnssec-deploy-repair` Skill 完成以下工作：

- 克隆或定位仓库，检查并安装运行依赖。
- 根据目标环境选择本机或 Docker，以及 BIND9 或 PowerDNS 后端。
- 调用现网诊断、一键部署、一键修复和典型错误 demo 命令。
- 解释 77 种 DNSViz DNSSEC 错误码、修复族、拓扑优先级和所需权限。
- 汇总修复前后结果、配置包位置、剩余错误和需要人工执行的外部操作。

可以直接向大模型提出类似请求：

```text
使用 dnssec-deploy-repair Skill，检查环境并在本地 BIND9 中为 example.org 部署 DNSSEC。

使用 dnssec-deploy-repair Skill，分析 capture.grok.json，
按拓扑优先级生成 PowerDNS 修复计划；执行前先列出所需权限。

使用 dnssec-deploy-repair Skill，在 Docker PowerDNS 环境中运行现网案例修复，
最后报告修复前后错误码和配置包路径。
```

大模型不是 DNSSEC 修复决策主体。错误码映射、依赖症状消解、拓扑优先级、
修复计划和 BIND9/PowerDNS 后端操作均由本项目的确定性规则和适配器实现。
大模型主要负责安装与调用工具、补全参数、协调工具之外的父区或注册商权限，
以及解释和汇总结果。没有大模型时，所有 CLI 和 Docker 工作流仍可独立运行。

Skill 覆盖 77 种 DNSSEC 相关错误码的知识与处置方法，但不表示 77 种错误都能
在当前两个后端中自动执行。涉及公网权威服务、注册商或父区 DS 的变更默认只
生成计划和配置包，必须在获得相应权限并经人工确认后执行。

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

上面的系统依赖已经包含 `dnsviz`，正常使用不需要再准备 DNSViz 源码目录。可选：如果你希望替换为本地新版 DNSViz 源码，可以把源码放在本项目目录下的 `dnsviz/`；没有这个目录时，工具会直接使用系统安装的 `dnsviz` 命令。核心部署、修复计划和修复执行都由本项目代码实现，不依赖外部 DFixer 仓库。

## 常用命令

### 1. 现网解析链记录 + 本地 DNSSEC 部署

适用于现网尚未部署 DNSSEC 的域名：工具会抓取现有解析记录，在本地生成 DNSSEC key、DS、签名 zone 和对应后端配置。

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

## Docker 运行

Docker 版本同样覆盖三条核心工作流：现网部署、现网错误修复、典型错误 demo。需要 Docker daemon 可用，并允许容器使用 `NET_ADMIN` capability。

对于未部署 DNSSEC 的现网域名，使用 Docker 版 `deploy-realcase` 即可生成本地 DNSSEC 部署配置包。

构建镜像：

```bash
./docker/docker_lab.sh build
./docker/powerdns_docker_lab.sh build
```

### 1. 现网解析链记录 + 本地 DNSSEC 部署

BIND9：

```bash
./docker/docker_lab.sh deploy-realcase example.org
```

PowerDNS：

```bash
./docker/powerdns_docker_lab.sh deploy-realcase example.org
```

### 2. 现网 DNSSEC 错误 + 本地规约修复

BIND9：

```bash
./docker/docker_lab.sh repair-realcase dnssec-failed.org
```

PowerDNS：

```bash
./docker/powerdns_docker_lab.sh repair-realcase dnssec-failed.org
```

### 3. 典型 DNSSEC 错误 demo

BIND9：

```bash
./docker/docker_lab.sh demo bad-ds
```

PowerDNS：

```bash
./docker/powerdns_docker_lab.sh demo bad-ds
```

Docker 输出目录：

```text
work-docker/              # BIND9 容器运行状态
work-powerdns-docker/     # PowerDNS 容器运行状态
realcase-live-docker/     # Docker 运行导出的配置包
```

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

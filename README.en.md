# DNSSEC Auto Deploy & Repair Lab

[中文](README.md) | English

This project is a local DNSSEC lab for BIND9 and PowerDNS. It fetches public-domain resolution-chain records and creates a controlled local `root -> parent -> child` authoritative environment for DNSSEC deployment, DNSSEC repair, and reproducible demos.

The local environment preserves source-shaped domain names. For example, `dnssec-failed.org.` becomes parent zone `org.` and child zone `dnssec-failed.org.`; `foo.bar.example.org.` becomes parent zone `bar.example.org.` and child zone `foo.bar.example.org.`. The tool does not rewrite public domains into a fixed test domain.

## Core Features

1. Fetch resolution-chain records for a public domain, create a local virtual DNS environment, deploy DNSSEC, and export readable BIND9/PowerDNS configuration files.
2. Fetch resolution-chain records for a public domain, create a local virtual DNS environment, repair DNSSEC deployment errors, and export readable BIND9/PowerDNS configuration files.
3. Provide BIND9/PowerDNS demos for typical DNSSEC errors.

For a public domain that has not deployed DNSSEC, use the first workflow directly: the tool reads the existing public resolution chain and service records, then generates a local DNSSEC-enabled BIND9/PowerDNS configuration bundle. From a repair perspective, this can also be treated as locally repairing a missing DNSSEC deployment.

## LLM Integration and Project Skill

The repository includes a project-level Skill for LLM clients:

```text
.trae/skills/dnssec-deploy-repair/
├── SKILL.md
└── references/
    ├── workflows.md
    └── error-codes.md
```

When this repository is opened in an LLM client that supports project-level
Skills, ask the model to use the `dnssec-deploy-repair` Skill to:

- clone or locate the repository and verify or install its dependencies;
- select native or Docker execution and the BIND9 or PowerDNS backend;
- invoke public diagnosis, one-command deployment, one-command repair, and
  typical error demos;
- explain 77 DNSViz DNSSEC error codes, repair families, topological
  priorities, and required authority;
- summarize before/after results, configuration bundle paths, residual
  errors, and external actions that still require an operator.

Example prompts:

```text
Use the dnssec-deploy-repair Skill to check the environment and deploy DNSSEC
for example.org in the local BIND9 lab.

Use the dnssec-deploy-repair Skill to analyze capture.grok.json and produce a
topologically ordered PowerDNS repair plan. List required permissions before
execution.

Use the dnssec-deploy-repair Skill to repair a public case in the Docker
PowerDNS lab, then report before/after error codes and the configuration bundle.
```

The LLM is not the DNSSEC repair decision engine. Error-code mapping,
dependent-symptom elimination, topological priority, repair planning, and
BIND9/PowerDNS mutations are implemented by deterministic project rules and
backend adapters. The LLM primarily installs and invokes the tool, completes
parameters, coordinates parent-zone or registrar authority outside the tool,
and explains the results. All CLI and Docker workflows also run without an
LLM.

The Skill contains knowledge and procedures for 77 DNSSEC-specific error
codes, but this does not mean that all 77 are automatically executable on both
current backends. Changes to public authoritative services, registrars, or
parent DS records are plan-and-export operations by default and require the
corresponding authority and explicit operator approval.

## Runtime Environment

Recommended system: Debian 12 / Ubuntu 22.04+. The tool starts local DNS services on port 53 and configures loopback IPs, so it is best used inside a devbox, VM, or container. `demo`, `realcase-demo`, and `repair-realcase` automatically clean up local DNS services when they finish.

Python **3.10 or newer is required** (the code uses PEP 604 `X | None` type syntax; Debian 12 / Ubuntu 22.04+ ship Python 3.11, which works out of the box). The system Python 3.9 on CentOS Stream 9 / RHEL 9 cannot run this tool — use the Docker image described below, or install Python 3.10+ via pyenv/uv.

Install system dependencies:

```bash
sudo apt-get update
sudo apt-get install -y \
  bind9 bind9-utils bind9-dnsutils dnsutils dnsviz \
  graphviz iproute2 libgraphviz-dev \
  pdns-server pdns-backend-bind \
  python3 python3-pip python3-pygraphviz python3-venv procps
```

Install Python dependencies:

```bash
python3 -m pip install --break-system-packages \
  faker pandas publicsuffixlist requests tldextract tqdm
```

The system dependency list above already installs `dnsviz`; normal usage does not require a DNSViz source tree. Optional: if you want to override it with a local newer DNSViz source tree, place the source under `dnsviz/` inside this project directory. Without that directory, the tool uses the system-installed `dnsviz` command. Core deployment, repair planning, and repair execution are implemented by this project and do not require an external DFixer repository.

## Common Commands

### 1. Public resolution chain + local DNSSEC deployment

Use this for public domains that have not deployed DNSSEC yet. The tool fetches existing DNS records and locally generates DNSSEC keys, DS records, signed zones, and backend configuration.

BIND9:

```bash
python3 dnssec_repair_engine.py deploy-realcase \
  --backend bind9 \
  --domain example.org
```

PowerDNS:

```bash
python3 dnssec_repair_engine.py deploy-realcase \
  --backend powerdns \
  --domain example.org
```

The JSON output includes `config_bundle`. Example output directories:

```text
realcase-live/example.org/deploy/bind9-config/
realcase-live/example.org/deploy/powerdns-config/
```

### 2. Public DNSSEC error + local normalized repair

BIND9:

```bash
python3 dnssec_lab.py repair-realcase \
  --domain dnssec-failed.org
```

PowerDNS:

```bash
python3 dnssec_lab.py repair-realcase \
  --domain dnssec-failed.org \
  --backend powerdns
```

Example output directories:

```text
realcase-live/dnssec-failed.org/bind9-config/
realcase-live/dnssec-failed.org/powerdns-config/
```

Built-in real-world case mapping:

```text
dnssec-failed.org        -> realcase-dnssec-failed-org
sigfail.ippacket.stream -> realcase-sigfail-ippacket-stream
al                       -> realcase-al-stale-ds-rollover
tamu.edu                 -> realcase-tamu-edu-expired-rrsig
```

Multi-level domains keep their original shape. Example:

```bash
python3 dnssec_lab.py realcase-demo realcase-dnssec-failed-org \
  --domain foo.bar.example.org \
  --backend bind9
```

This creates:

```text
child zone  = foo.bar.example.org.
parent zone = bar.example.org.
```

### 3. Typical DNSSEC error demos

BIND9:

```bash
python3 dnssec_lab.py demo bad-ds
```

PowerDNS:

```bash
python3 powerdns_lab.py demo bad-ds
```

Scenarios are defined in `dnssec_scenarios/`, including `bad-ds`, `expired-rrsig`, `signature-invalid`, and `missing-rrsig`.

## Docker Usage

The Docker version supports the same three core workflows: public-domain deployment, public DNSSEC error repair, and typical error demos. Docker daemon must be available, and the container needs the `NET_ADMIN` capability.

For a public domain without DNSSEC, use Docker `deploy-realcase` to generate a local DNSSEC deployment bundle.

Build images:

```bash
./docker/docker_lab.sh build
./docker/powerdns_docker_lab.sh build
```

### 1. Public resolution chain + local DNSSEC deployment

BIND9:

```bash
./docker/docker_lab.sh deploy-realcase example.org
```

PowerDNS:

```bash
./docker/powerdns_docker_lab.sh deploy-realcase example.org
```

### 2. Public DNSSEC error + local normalized repair

BIND9:

```bash
./docker/docker_lab.sh repair-realcase dnssec-failed.org
```

PowerDNS:

```bash
./docker/powerdns_docker_lab.sh repair-realcase dnssec-failed.org
```

### 3. Typical DNSSEC error demos

BIND9:

```bash
./docker/docker_lab.sh demo bad-ds
```

PowerDNS:

```bash
./docker/powerdns_docker_lab.sh demo bad-ds
```

Docker output directories:

```text
work-docker/              # BIND9 container runtime state
work-powerdns-docker/     # PowerDNS container runtime state
realcase-live-docker/     # exported config bundles from Docker runs
```

## Output Files

Real-world case outputs are written under `realcase-live/<domain>/`. For example:

```text
realcase-live/dnssec-failed.org/
├── dnssec-failed.org.live.probe.json
├── dnssec-failed.org.live.grok.json
├── bind9-config/
└── powerdns-config/
```

The top-level `live.*.json` files store DNSViz observations from the public domain:

- `*.live.probe.json`: raw DNSViz probe data.
- `*.live.grok.json`: summarized DNSViz diagnosis.

BIND9 bundle:

```text
bind9-config/
├── named-conf/
├── zones/
├── dnsviz-output/
└── README.txt
```

PowerDNS bundle:

```text
powerdns-config/
├── powerdns-conf/
├── resolver-conf/
├── powerdns-dnssec-db/
├── zones/
├── dnsviz-output/
└── README.txt
```

Key directories:

- `zones/`: repaired zone files. `db.*` files are unsigned zones; `db.*.signed` files are DNSSEC-signed zones.
- `dnsviz-output/`: before/after DNSViz summaries and `repair-plan.json`.
- `named-conf/`: BIND9 authoritative and resolver configuration.
- `powerdns-conf/`: PowerDNS authoritative configuration.
- `powerdns-dnssec-db/`: PowerDNS DNSSEC metadata sqlite files.

`work/` and `realcase-live/` are generated runtime directories and can be deleted.

## Tests

```bash
python3 -m unittest discover -s tests
```

## GitHub Upload Notes

Upload the `dnssec-local-lab/` directory as the repository root. Runtime artifacts should not be committed. The included `.gitignore` excludes:

```text
work/
realcase-live/
artifacts/
__pycache__/
*.pyc
*.log
*.pid
```

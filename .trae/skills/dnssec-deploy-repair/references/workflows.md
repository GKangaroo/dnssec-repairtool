# Installation And Operational Workflows

## Clone The Repository

The project repository is:

```text
https://github.com/GKangaroo/dnssec-repairtool
```

When it is not already available locally:

```bash
git clone https://github.com/GKangaroo/dnssec-repairtool.git
cd dnssec-repairtool
```

When it already exists, do not clone a second copy. Enter the existing
repository instead. Run all following commands from the directory containing
`dnssec_repair_engine.py`.

## Install On Debian Or Ubuntu

The host workflow binds local port 53 and configures loopback addresses. Use a
development machine, VM, or container where these changes are acceptable.

```bash
sudo apt-get update
sudo apt-get install -y \
  bind9 bind9-utils bind9-dnsutils dnsutils dnsviz \
  graphviz iproute2 libgraphviz-dev \
  pdns-server pdns-backend-bind \
  python3 python3-pip python3-pygraphviz python3-venv procps

python3 -m pip install --break-system-packages \
  faker pandas publicsuffixlist requests tldextract tqdm
```

Verify the installation:

```bash
command -v named
command -v dnssec-signzone
command -v dnsviz
command -v pdns_server
python3 -m unittest discover -s tests
```

Use the repository's optional `dnsviz/` source tree when present; otherwise the
tool uses the system `dnsviz` command. No external DFixer repository is needed.

## Docker Setup

Docker requires a running daemon and permission to use `NET_ADMIN`.

```bash
./docker/docker_lab.sh build
./docker/powerdns_docker_lab.sh build
```

Use `./docker/docker_lab.sh daemon` only when the current machine lacks a
running Docker daemon and the wrapper supports starting one.

## Plan From Existing DNSViz Grok

Plan only; this does not mutate the backend:

```bash
python3 dnssec_repair_engine.py plan-grok \
  --backend bind9 \
  --grok path/to/capture.grok.json \
  --out work/repair-plan.json
```

For PowerDNS, replace `bind9` with `powerdns`.

To inspect only the current highest-priority code:

```bash
python3 dnsviz_grok_adapter.py path/to/capture.grok.json \
  --backend bind9 \
  --plan \
  --topological
```

Inspect:

- `code`: exact DNSViz code;
- `family`: normalized repair family;
- `executor`: child, parent, multi-authority, or server behavior;
- `required_permission`: authority needed before execution;
- `action`: intended repair;
- `demo_action`: local-lab implementation.

## Execute A Known Grok Capture

This mutates and restarts the controlled local backend:

```bash
python3 dnssec_repair_engine.py execute-grok-controlled \
  --backend bind9 \
  --grok path/to/capture.grok.json \
  --out work/controlled-repair-result.json
```

Use `--rotate-keys` only when key replacement is required. This command applies
all instructions in the plan. For multiple observed codes, prefer the iterative
workflow below so each pass repairs one root cause and diagnoses again.

The lower-level command supports one topological repair:

```bash
python3 controlled_zone_repair.py \
  --backend powerdns \
  --grok path/to/capture.grok.json \
  --topological \
  --out work/topological-repair-result.json
```

## Iterative Controlled Repair

This is the preferred closed loop for an already-running controlled lab:

```bash
python3 dnssec_repair_engine.py repair-controlled \
  --backend bind9 \
  --prefix repair-controlled \
  --out work/iterative-repair-result.json
```

Use `iterate-controlled` when the iteration limit must be set explicitly:

```bash
python3 dnssec_repair_engine.py iterate-controlled \
  --backend powerdns \
  --max-iterations 5 \
  --prefix iterative-repair \
  --out work/iterative-repair-result.json
```

Each iteration performs:

```text
DNSViz diagnose
-> choose one topological code
-> mutate zone/backend
-> resign
-> refresh service
-> DNSViz diagnose again
```

Success requires `"converged": true` and `"final_codes": []`.

## Deploy DNSSEC For A Public Domain In The Local Lab

This captures the public DNSViz state, imports ordinary records from an
authoritative zone export or AXFR, generates fresh local keys and DS, constructs
the local parent/child chain, starts the backend, verifies it, and exports a
configuration bundle. It does not publish DS at the real registrar.

Recursive DNS is not a complete zone-enumeration mechanism. Use
`--allow-partial-records` only for an explicitly incomplete lab demo.

BIND9:

```bash
python3 dnssec_repair_engine.py deploy-realcase \
  --backend bind9 \
  --domain example.org \
  --zone-file /path/to/db.example.org
```

PowerDNS:

```bash
python3 dnssec_repair_engine.py deploy-realcase \
  --backend powerdns \
  --domain example.org \
  --axfr-server 192.0.2.53
```

Docker equivalents:

```bash
./docker/docker_lab.sh deploy-realcase example.org --allow-partial-records
./docker/powerdns_docker_lab.sh deploy-realcase example.org --allow-partial-records
```

Expected bundles:

```text
realcase-live/<domain>/deploy/bind9-config/
realcase-live/<domain>/deploy/powerdns-config/
```

Default bundles target the local lab (listen-on 127.10.0.x, a single `ns.`
host) and are not directly deployable. To export a production-ready bundle,
add `--ns-names` and `--public-ip`:

```bash
python3 dnssec_repair_engine.py deploy-realcase \
  --backend bind9 \
  --domain example.org \
  --allow-partial-records \
  --ns-names ns1,ns2 \
  --public-ip 203.0.113.10
```

`--ns-names` must exactly match the parent-side delegation and glue, or global
resolution goes LAME. With `--public-ip` the export rewrites the child NS glue
A records to that IP, re-signs the zone with the same keys (DS/CDS/CDNSKEY are
unaffected), sets `listen-on any` (PowerDNS: `local-address=0.0.0.0`), and
relativizes paths so the bundle is portable (`named -c named-conf/<zone>.conf`
from the bundle root). The child then publishes CDS/CDNSKEY and the registry
CDS scanner (e.g. fuyu) syncs the DS into the parent automatically; no manual
registrar DS entry is needed. The bundle does not include key material — carry
the lab `keys/` directory or regenerate keys on the target host.

## Repair A Public DNSSEC Case In The Local Lab

The command captures an arbitrary public case, builds its plan directly from
the DNSViz grok result, and applies that plan to a local controlled copy:

```bash
python3 dnssec_lab.py repair-realcase \
  --domain example.org \
  --backend bind9 \
  --zone-file /path/to/db.example.org

python3 dnssec_lab.py repair-realcase \
  --domain example.org \
  --backend powerdns \
  --axfr-server 192.0.2.53
```

Docker equivalents:

```bash
./docker/docker_lab.sh repair-realcase example.org --allow-partial-records
./docker/powerdns_docker_lab.sh repair-realcase example.org --allow-partial-records
```

Use `--grok capture.grok.json` to operate from an existing capture without live
network access. Do not describe these commands as modifying the public domain.
`local_converged` is only the controlled-chain verification result, and
`public_changes_applied` remains false.

## Run Error Demos

```bash
python3 dnssec_lab.py demo bad-ds
python3 powerdns_lab.py demo bad-ds

./docker/docker_lab.sh demo bad-ds
./docker/powerdns_docker_lab.sh demo bad-ds
```

Scenario names are defined in `dnssec_scenarios/`.

## Backend Effects

### BIND9

The adapter edits unsigned zone files, signs child/parent/root zones, writes
BIND configuration when deploying, and restarts local BIND9 lab services.

Check generated configuration before deployment:

```bash
named-checkconf path/to/named.conf
named-checkzone example.org path/to/db.example.org.signed
```

### PowerDNS

The project uses PowerDNS's bind backend with presigned zones. The adapter:

1. stops the local PowerDNS lab;
2. updates zone files;
3. regenerates `powerdns-conf/`;
4. regenerates `powerdns-dnssec-db/` sqlite metadata;
5. writes the validating resolver configuration;
6. starts services.

Never copy only the zone files. Keep the exported
`powerdns-dnssec-db/` metadata with the configuration bundle.

## Output Inspection

Typical real-case output:

```text
realcase-live/<domain>/
├── <domain>.live.probe.json
├── <domain>.live.grok.json
├── bind9-config/
└── powerdns-config/
```

Important bundle directories:

- `zones/`: unsigned and signed zones;
- `dnsviz-output/`: before/after grok and repair plan;
- `named-conf/`: BIND9 configuration;
- `powerdns-conf/`: PowerDNS configuration;
- `resolver-conf/`: validating resolver configuration;
- `powerdns-dnssec-db/`: PowerDNS DNSSEC metadata.

## Permission Boundaries

- `child-zone repair`: child zone/backend and signing keys.
- `parent-side repair`: parent zone, registrar, or registry API.
- `multi-auth sync`: all authoritative servers or publication pipeline.
- `server-behavior repair`: authoritative implementation, proxy, or gateway.
- `inactive policy`: retain the plan but do not claim a currently reproducible
  DNSViz failure.

When required authority is unavailable, produce a plan and exact manual action;
do not run a partial change that can break the chain.

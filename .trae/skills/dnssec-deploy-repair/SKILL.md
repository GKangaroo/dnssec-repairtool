---
name: "dnssec-deploy-repair"
description: "Installs and operates the DNSSEC lab, maps 77 DNSViz DNSSEC codes to prioritized repairs, and drives BIND9/PowerDNS workflows. Invoke for DNSSEC diagnosis, deployment, repair, or demos."
---

# DNSSEC Deploy And Repair

This skill operates the `GKangaroo/dnssec-repairtool` repository:

```text
https://github.com/GKangaroo/dnssec-repairtool
```

Use it to clone and install the DNSSEC repair tool, interpret DNSViz grok
results, select root-cause-first repairs, and operate its controlled BIND9 or
PowerDNS lab.

## Scope And Safety

The tool controls a local `root -> parent -> child` authority chain. It can:

- capture public DNS data;
- reproduce or repair that data in a controlled local lab;
- start, stop, reload, and regenerate local BIND9/PowerDNS services;
- export BIND9 or PowerDNS configuration bundles.

It does not automatically change a public authoritative service, registrar, or
parent registry. `repair-realcase` repairs a local reproduction. Treat an
exported bundle as a deployment candidate that still needs operator review.

Before any state-changing command:

1. Identify the backend: `bind9` or `powerdns`.
2. Identify the target: local lab, Docker lab, or an external service.
3. Confirm control of child signing data and, when needed, parent DS or all
   authoritative servers.
4. Preserve ordinary business records. Do not replace a zone from a demo
   template when repairing a real-case clone.
5. Use `--rotate-keys` only for invalid/revoked/unsupported keys or when the
   operator explicitly requests rotation.

If the target is external production, stop at diagnosis, repair plan, and
exported configuration unless the user has explicitly supplied the deployment
mechanism and authorized the change.

## Locate The Tool

If the repository is not present, clone it:

```bash
git clone https://github.com/GKangaroo/dnssec-repairtool.git
cd dnssec-repairtool
```

If it is already present, find its directory by locating:

```text
dnssec_repair_engine.py
dnssec_lab.py
powerdns_lab.py
docker/docker_lab.sh
docker/powerdns_docker_lab.sh
```

Run commands from that directory. Call it `$LAB_ROOT` in explanations. Never
hard-code a developer-specific absolute path.

## Load References

- Read [workflows.md](references/workflows.md) for installation, command
  selection, backend effects, outputs, and verification.
- Read [error-codes.md](references/error-codes.md) when a DNSViz code is
  present, when explaining repair priority, or when producing a manual repair
  procedure.

Repository code is authoritative if it differs from these references:

- `dnssec_repair_engine.py`: ordering and plan construction;
- `dnssec_repair_catalog.py`: repair families, permissions, and actions;
- `dnsviz_grok_adapter.py`: grok parsing;
- `zone_backend_adapter.py`: concrete BIND9/PowerDNS mutations;
- `controlled_zone_repair.py`: one-pass controlled repair;
- `iterative_controlled_repair.py`: diagnose-repair-verify loop;
- `controlled_dnssec_deploy.py`: controlled deployment;
- `docs/dnsviz_error_coverage.json`: DNSViz coverage status.

## Decision Flow

1. **Install or verify prerequisites.** Use the native or Docker path from
   `workflows.md`. Prefer Docker when host port 53, loopback addresses, or
   service management should remain isolated.
2. **Capture or load diagnosis.** Accept an existing `*.grok.json`, or use the
   real-case command to capture the public chain.
3. **Plan before mutation.** Run `plan-grok`; inspect every instruction's
   `code`, `family`, `executor`, `required_permission`, and `action`.
4. **Select the root cause.** Use `--topological` or the iterative workflow.
   Never repair all observed codes blindly when some are dependent symptoms.
5. **Check authority.** Parent DS and delegation repairs require parent or
   registrar access. Multi-authority inconsistencies require all authoritative
   servers or the publication pipeline. Server-behavior errors require server
   configuration or implementation access.
6. **Execute in the controlled backend.** Use `execute-grok-controlled` for a
   known grok capture or `repair-controlled` for repeated DNSViz feedback.
7. **Verify convergence.** Require a fresh DNSViz run and an empty
   `final_codes`. Also query each authoritative server when the family is
   `multi_auth_dnskey_sync` or `cds_cdnskey_multi_signal`.
8. **Report artifacts and residual limits.** Include the plan path, before/after
   grok paths, configuration bundle, actions taken, remaining codes, and any
   permission not held.

## Priority Semantics

The 77-code catalog is ordered by
`dnssec_repair_engine.TOPOLOGICAL_CODE_ORDER`. Smaller ranks are repaired first.
Codes absent from that tuple use the engine's fallback priority and sort by
code. `NO_SEP`, `MISSING_RRSIG_FOR_ALG_DS`, and `REVOKED_NOT_SIGNING` are
dependent symptoms in the engine; prefer an independent cause when present.

Typical root-cause order is:

```text
multi-authority DNSKEY drift
-> revoked/invalid DNSKEY
-> parent DS and key-chain errors
-> RRSIG errors
-> signature time/TTL errors
-> NSEC/NSEC3 proof errors
-> delegation bitmap errors
-> CDS/CDNSKEY automation errors
-> algorithm migration
-> inactive-policy/server-behavior fallbacks
```

Do not infer success from a service restart. Success means the fresh diagnosis
contains no target DNSViz errors.

## Repair Execution Model

The zone-file adapter currently applies these concrete operations:

- key-reset families: rotate child and parent keys, refresh root and parent DS;
- CDS/CDNSKEY conflicts: remove conflicting child automation signals;
- DS/key-chain families: replace parent DS from the current child KSK;
- all data-plane families: resign child, parent, and root zones;
- BIND9: restart local lab services;
- PowerDNS: rewrite bind-backend configuration and DNSSEC sqlite metadata,
  then restart services.

This is broader than some catalog actions. For example, a simple signature
error still triggers whole-chain resigning in the current adapter. State that
fact when reporting what was changed.

## Response Contract

For diagnosis or execution, return:

```text
Target:
Backend:
Mode: plan-only | local-controlled | Docker-controlled | external-export
Observed codes:
Selected code and priority:
Repair family:
Required authority:
Planned or executed actions:
Verification:
Artifacts:
Residual risk or manual step:
```

Do not claim that all 154 DNSViz diagnostics are automatically repairable. This
skill's 77-code catalog covers DNSSEC-specific DNAME, CDS/CDNSKEY, DNSKEY, DS,
NSEC/NSEC3, RRSIG, and trust-anchor diagnostics. Network, EDNS, cookie, generic
response, and glue diagnostics need separate operational handling.

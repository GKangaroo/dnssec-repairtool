#!/usr/bin/env python3
import argparse
import subprocess
import sys
from pathlib import Path

LAB_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB_ROOT))

from dnssec_scenarios import get as get_scenario
from dnssec_scenarios import names as scenario_names


ROOT = LAB_ROOT
RESULTS = ROOT / "artifacts" / "powerdns-results"


def parse_codes(log_text: str) -> tuple[str, str]:
    lines = [line for line in log_text.splitlines() if "DNSViz error codes:" in line]
    before = lines[0].split("DNSViz error codes: ", 1)[1] if len(lines) >= 1 else "<missing>"
    after = lines[1].split("DNSViz error codes: ", 1)[1] if len(lines) >= 2 else "<missing>"
    return before, after


def code_set(codes: str) -> set[str]:
    if codes in {"<none>", "<missing>"}:
        return set()
    return {item.strip() for item in codes.split(",") if item.strip()}


def run_scenario(scenario: str, timeout: int) -> tuple[str, str, bool, bool, int]:
    RESULTS.mkdir(exist_ok=True)
    log_path = RESULTS / f"{scenario}.log"
    cmd = [sys.executable, "powerdns_lab.py", "demo", scenario]
    proc = subprocess.run(
        cmd,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
        check=False,
    )
    log_path.write_text(proc.stdout, encoding="utf-8")
    before, after = parse_codes(proc.stdout)
    config = get_scenario(scenario)
    expected = set(config.expected_codes if config else ())
    matched = bool(expected & code_set(before))
    fixed = after == "<none>"
    return before, after, matched, fixed, proc.returncode


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate PowerDNS demo target-code coverage.")
    parser.add_argument("scenarios", nargs="*", help="scenario names; default: all registered scenarios")
    parser.add_argument("--timeout", type=int, default=90)
    args = parser.parse_args()

    scenarios = args.scenarios or scenario_names()
    summary = []
    for scenario in scenarios:
        before, after, matched, fixed, returncode = run_scenario(scenario, args.timeout)
        status = "target-ok" if matched and fixed and returncode == 0 else "target-miss"
        if matched and not fixed and returncode == 0:
            status = "fix-dirty"
        if returncode != 0:
            status = f"failed:{returncode}"
        summary.append((status, scenario, before, after))
        print(f"{status}\t{scenario}\t{before}\t{after}", flush=True)
        subprocess.run([sys.executable, "powerdns_lab.py", "stop"], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    summary_path = RESULTS / "summary.tsv"
    summary_path.write_text(
        "\n".join("\t".join(row) for row in summary) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()

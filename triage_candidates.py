#!/usr/bin/env python3
"""Rank candidate chains: new routes first, known public families and dead routes last.

Writes triage.json, chains.ranked (every candidate, review order) and
chains.review (one representative per cluster). No candidate is removed.
"""
import argparse
import json
import sys
import zipfile
from pathlib import Path

import yaml

from scan_rules.inventory import inventory
from scan_rules.runner import read_candidates
from scan_rules.triage import triage_chains, triage_prepared, write_review


def print_summary(report):
    summary = report["summary"]
    print(f"{summary['candidates']} candidates in {summary['clusters']} review clusters: "
          f"{summary['novel_unblocked']} novel and not blocked, {summary['known']} known-family, "
          f"{summary['blocked']} blocked on this build.")
    if summary["by_family"]:
        print("Known families: " + ", ".join(f"{k} ({v})" for k, v in sorted(summary["by_family"].items())))
    print("Effects: " + ", ".join(f"{k} ({v})" for k, v in sorted(summary["by_effect"].items())))
    if report.get("class_facts") != "checked":
        print("Class facts unavailable: bytecode-backed mitigations are reported as unverified.")
    print(f"Review first: {report['files']['review']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--prepared", help="Prepared or scanned directory (uses its manifest, classpath and chains)")
    inputs.add_argument("--chains", help="Existing chains file from any run")
    parser.add_argument("--chains-file", help="With --prepared: triage this chains file instead of <prepared>/chains")
    parser.add_argument("--runtime-version", help="With --chains: target runtime, e.g. 1.8.0_432")
    parser.add_argument("--classpath", action="append", default=[],
                        help="With --chains: runtime/dependency JARs used as mitigation evidence; repeatable")
    parser.add_argument("--output", help="With --chains: directory for review files (default: next to the chains file)")
    args = parser.parse_args()
    try:
        if args.prepared:
            report = triage_prepared(args.prepared, args.chains_file)
        else:
            chains = read_candidates(Path(args.chains))
            if chains["errors"]:
                print("Candidate file warnings: " + "; ".join(chains["errors"]), file=sys.stderr)
            classes = inventory([Path(p).expanduser().resolve(strict=True) for p in args.classpath]) if args.classpath else None
            report = triage_chains(chains["chains"], classes=classes, runtime=args.runtime_version)
            report["class_facts"] = "checked" if classes is not None else "unavailable"
            output = Path(args.output or Path(args.chains).parent)
            output.mkdir(parents=True, exist_ok=True)
            write_review(output, chains["chains"], report)
    except (ValueError, OSError, KeyError, zipfile.BadZipFile, yaml.YAMLError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print_summary(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())

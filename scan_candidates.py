#!/usr/bin/env python3
"""Prepare and run bounded native-deserialization candidate generation."""
import argparse
from pathlib import Path
import sys
import zipfile

from prepare_scan import PROFILES, prepare
from scan_rules.runner import run_backend
from scan_rules.triage import triage_prepared
from triage_candidates import print_summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--app", action="append")
    inputs.add_argument("--prepared", help="Run an existing, unscanned preparation (including enhance_scan.py output)")
    parser.add_argument("--lib", action="append", default=[])
    parser.add_argument("--java-home")
    parser.add_argument("--java8-home", help="Deprecated alias for --java-home")
    parser.add_argument("--output", help="Fresh directory for configuration, progress and candidates")
    parser.add_argument("--profile", action="append", choices=("auto", *PROFILES), help="Default auto: chosen from the target bytecode")
    parser.add_argument("--timeout", type=int, default=300, help="Backend wall-time limit in seconds")
    parser.add_argument("--heap-mb", type=int, default=4096)
    parser.add_argument("--stack-mb", type=int, default=16)
    parser.add_argument("--java", default="java", help="JDK 17+ java executable that runs Flash")
    parser.add_argument("--backend", choices=("auto", "stock", "optimized"), default="auto", help="Use validated string parsing optimization when available")
    parser.add_argument("--collector", choices=("stock", "fair"), default="stock", help="Experimental fair mode interleaves sinks and reports exhausted budgets")
    args = parser.parse_args()
    if args.timeout <= 0 or args.heap_mb < 256 or args.stack_mb < 1:
        parser.error("Use a positive timeout, heap >= 256 MiB, and stack >= 1 MiB.")
    java_home = args.java_home or args.java8_home
    if args.prepared and (args.lib or args.profile or java_home or args.output):
        parser.error("--prepared uses its existing configuration; omit --lib, --profile, --java-home and --output.")
    if args.app and (not java_home or not args.output):
        parser.error("--app requires --java-home and --output.")
    try:
        if args.app:
            print("Preparing target classpath and native-deserialization rules…", flush=True)
            prepare(args.app, args.lib, java_home, args.output, args.profile or ["auto"])
        folder = args.prepared or args.output
        print(f"Searching candidates. Progress: {Path(folder).absolute() / 'stage1.json'}", flush=True)
        report = run_backend(folder, timeout=args.timeout, heap_mb=args.heap_mb,
                             stack_mb=args.stack_mb, java=args.java, backend=args.backend, collector=args.collector)
    except (ValueError, OSError, zipfile.BadZipFile) as exc:
        parser.error(str(exc))
    except KeyboardInterrupt:
        print("Preparation interrupted.", file=sys.stderr)
        return 130
    print(f"{report['status']}: {report['candidate_count']} candidate chains. {report['message']}")
    optimization = report['backend_optimization']
    print(f"Backend: {optimization['mode']}" + (f" ({optimization['fallback_reason']})" if optimization.get('fallback_reason') else ""))
    print(f"Candidates: {report['chains_file']}")
    if report["candidate_count"]:
        try:
            print_summary(triage_prepared(folder))
        except (ValueError, OSError) as exc:
            print(f"Triage skipped: {exc}", file=sys.stderr)
    return {"completed": 0, "partial": 2, "cancelled": 130, "failed": 1}[report["status"]]


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Measure recall and cost on vulnerable releases of public gadget families.

For each case, run the default automatic configuration with a fixed budget and
report whether any candidate uses the family's core gadget and ends at an
expected effect, how far down the review list the best such candidate is, and
how long the scan took. Inputs are read from a local Maven repository; nothing
is downloaded and no target code is executed.
"""
import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

from prepare_scan import prepare
from scan_rules.runner import atomic_report, run_backend
from scan_rules.triage import triage_prepared

ROOT = Path(__file__).resolve().parent
CASES = ROOT / "evaluation" / "recall-cases.json"


def measure(case, repository, java8_home, output, timeout, heap_mb, profiles):
    paths = [repository / case["app"], *(repository / lib for lib in case["libs"])]
    missing = [str(p) for p in paths if not p.is_file()]
    if missing:
        return {"id": case["id"], "status": "skipped", "reason": "missing " + ", ".join(missing)}
    folder = output / case["id"]
    started = time.monotonic()
    manifest = prepare([paths[0]], paths[1:], java8_home, folder, profiles)
    prepared_seconds = round(time.monotonic() - started, 1)
    report = run_backend(folder, timeout=timeout, heap_mb=heap_mb, backend="auto", collector="fair")
    triage = triage_prepared(folder) if report["candidate_count"] else None
    hits = [c for c in (triage or {}).get("candidates", ()) if case["family"] in c["families"]]
    effect_hits = [c for c in hits if c["effect"] in case["effects"]]
    return {"id": case["id"], "family": case["family"], "status": report["status"],
            "inputs": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
            "profiles": list(manifest["profile_selection"]),
            "prepare_seconds": prepared_seconds, "search_seconds": report.get("elapsed_seconds"),
            "candidates": report["candidate_count"],
            "clusters": triage["summary"]["clusters"] if triage else 0,
            "family_candidates": len(hits), "family_effect_candidates": len(effect_hits),
            "recall": bool(effect_hits),
            "best_rank": min((c["rank"] for c in effect_hits), default=None),
            "budget_exhausted": (report.get("collector") or {}).get("budget_exhausted")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--java8-home", required=True)
    parser.add_argument("--output", required=True, help="Fresh directory for per-case scans and recall.json")
    parser.add_argument("--maven-repository", default=str(Path.home() / ".m2/repository"))
    parser.add_argument("--case", action="append", help="Case ID; repeatable (default: all)")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--heap-mb", type=int, default=8192)
    parser.add_argument("--profile", action="append", help="Override the default auto profile selection")
    args = parser.parse_args()
    output = Path(args.output).expanduser().absolute()
    if output.exists():
        parser.error("Output already exists; choose a fresh directory.")
    output.mkdir(parents=True)
    catalog = json.loads(CASES.read_text())
    cases = [c for c in catalog["cases"] if not args.case or c["id"] in args.case]
    if args.case and len(cases) != len(set(args.case)):
        parser.error("Unknown case ID.")
    results = []
    for case in cases:
        print(f"{case['id']}: scanning…", flush=True)
        try:
            result = measure(case, Path(args.maven_repository).expanduser(), args.java8_home, output,
                             args.timeout, args.heap_mb, args.profile or ["auto"])
        except (ValueError, OSError) as exc:
            result = {"id": case["id"], "status": "failed", "reason": f"{type(exc).__name__}: {exc}"}
        results.append(result)
        atomic_report(output / "recall.json", {"schema_version": 1, "catalog_sha256": hashlib.sha256(CASES.read_bytes()).hexdigest(),
                                               "timeout": args.timeout, "heap_mb": args.heap_mb, "results": results})
        print(f"{case['id']}: {result['status']}, recall={result.get('recall')}, best_rank={result.get('best_rank')}, "
              f"family={result.get('family_candidates')}, candidates={result.get('candidates')}, "
              f"search={result.get('search_seconds')}s", flush=True)
    found = sum(bool(r.get("recall")) for r in results)
    print(f"Recall: {found}/{len(results)} families reached an expected effect within {args.timeout}s per case.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

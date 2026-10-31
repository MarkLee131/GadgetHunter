#!/usr/bin/env python3
"""Reconnect dynamic-proxy gadget chains from a --proxy-roots scan.

The backend cannot follow a java.lang.reflect.Proxy built during deserialization into
its handler's invoke. Prepare a scan with `prepare_scan.py --proxy-roots` so the backend
emits native-callback chains and handler fragments separately, then run this to stitch
them where a chain reaches a controllable receiver that could be a proxy. Output is a
ranked list of review leads, written to <scan>/proxy_stitch.json, not proven chains.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan_rules.proxy_stitch import stitch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan", required=True, help="A scanned directory prepared with --proxy-roots")
    parser.add_argument("--cap", type=int, default=500, help="Maximum leads to emit")
    parser.add_argument("--output", help="Write JSON here (default <scan>/proxy_stitch.json)")
    args = parser.parse_args()

    leads, prefixes, fragments = stitch(args.scan, cap=args.cap)
    output = Path(args.output) if args.output else Path(args.scan) / "proxy_stitch.json"
    output.write_text(json.dumps({
        "schema_version": 1,
        "note": "Permissive dynamic-proxy stitch leads; the handler is attacker-chosen, so review each.",
        "controllable_prefixes": prefixes,
        "handler_fragments": fragments,
        "leads": leads,
    }, indent=2) + "\n")
    print(f"{len(leads)} proxy-stitch leads from {prefixes} controllable prefixes and {fragments} handler fragments.")
    for lead in leads[:5]:
        print(f"  [{lead['priority']}] inject at {lead['inject_at'].split('.')[-2] if '.' in lead['inject_at'] else lead['inject_at']}"
              f".{lead['inject_at'].split('.')[-1]} -> {lead['handler'].split(':')[0].split('.')[-1]}.invoke"
              f" -> {lead['sink'].split(':')[0].split('.')[-1]}")
    print(f"Leads written to {output}; these are review hypotheses, not verified chains.")


if __name__ == "__main__":
    main()

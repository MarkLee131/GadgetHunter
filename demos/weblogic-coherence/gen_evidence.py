#!/usr/bin/env python3
"""Generate genuine evidence for the WebLogic Coherence filter-rediscovery demo.

Runs two real GadgetHunter components against the actual WebLogic Coherence
bytecode and its two default serialization filters, and writes evidence.json:

  1. tools.analysis.deserialization_filter.decide() -- the per-class allow/deny
     decision of a target's serial filter -- for each Coherence extractor under
     the WebLogic 14.1.1 GA filter and the WebLogic 15.1.1 filter.

  2. scan_rules.inventory -- the same bytecode reader the Stage-1 scanner uses --
     to confirm the reflective sink reachable inside each extractor's trigger
     method (e.g. UniversalExtractor.extract -> java.lang.reflect.Method.invoke).

Nothing here is hand-written: every verdict and every reachability fact is read
from the real module and the real jar. The demo page renders this file verbatim.

Usage:
  gen_evidence.py --coherence <coherence-14.1.1.jar> \
                  --filter-1411 <wl1411.filter> --filter-1511 <wl15.filter> \
                  --output evidence.json
"""
import argparse
import datetime as dt
import json
import sys
import zipfile
import tempfile
import shutil
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "multi-agents"))

from tools.analysis.deserialization_filter import load_filter
from scan_rules.inventory import inventory, instructions, operand_reference

# Coherence extractor/updater gadget classes, tagged with the public CVE whose
# gadget they are. "trigger" is the deserialization-reachable method to inspect.
GADGETS = [
    ("com.tangosol.util.extractor.ReflectionExtractor",  "extract", "CVE-2020-2555"),
    ("com.tangosol.util.extractor.UniversalExtractor",   "extract", "CVE-2020-2883 / CVE-2020-14756"),
    ("com.tangosol.util.extractor.ComparisonValueExtractor", "extract", "CVE-2020-2883"),
    ("com.tangosol.util.extractor.ConditionalExtractor", "extract", "CVE-2020-14825"),
    ("com.tangosol.util.extractor.ScriptValueExtractor", "extract", "CVE-2021-2135"),
    ("com.tangosol.util.extractor.UniversalUpdater",     "update",  "CVE-2020-2883 family"),
    ("com.tangosol.util.extractor.ReflectionUpdater",    "update",  "CVE-2020-2883 family"),
]
# Reflective / scripting sinks the Stage-1 scanner treats as dangerous.
SINKS = {
    ("java.lang.reflect.Method", "invoke"),
    ("java.lang.reflect.Constructor", "newInstance"),
    ("javax.script.ScriptEngine", "eval"),
    ("java.lang.Class", "forName"),
}
CALL_OPS = (0xb6, 0xb7, 0xb8, 0xb9)


def unpack_classes(jar, dest, prefix="com/tangosol/util/extractor/"):
    with zipfile.ZipFile(jar) as z:
        for e in z.infolist():
            fn = e.filename
            if fn.startswith(prefix) and fn.endswith(".class"):
                out = Path(dest) / fn
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(z.read(e))


def reachable_sink(cls_obj, method_name):
    """Return the first dangerous sink called inside the named method, or None."""
    for m in cls_obj.methods:
        if m.name != method_name or m.code is None:
            continue
        try:
            ops = list(instructions(m.code))
        except ValueError:
            continue
        for off, op in ops:
            if op not in CALL_OPS:
                continue
            ref = operand_reference(m.code, off)
            if not ref:
                continue
            owner, name, _ = ref
            if (owner, name) in SINKS:
                return f"{owner}.{name}"
    return None


def coherence_version(jar):
    try:
        with zipfile.ZipFile(jar) as z:
            mf = z.read("META-INF/MANIFEST.MF").decode("utf-8", "replace")
        for line in mf.splitlines():
            if line.startswith("Implementation-Version:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return "unknown"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--coherence", required=True, help="WebLogic 14.1.1 coherence.jar")
    ap.add_argument("--filter-1411", required=True)
    ap.add_argument("--filter-1511", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    f1411 = load_filter(args.filter_1411)
    f1511 = load_filter(args.filter_1511)

    tmp = tempfile.mkdtemp(prefix="cohev_")
    try:
        unpack_classes(args.coherence, tmp)
        classes = inventory([Path(tmp)], include_code=True, max_major=65)
    finally:
        pass

    rows = []
    for cls, trigger, cve in GADGETS:
        obj = classes.get(cls)
        sink = reachable_sink(obj, trigger) if obj else None
        d1411 = f1411.decide(cls)
        d1511 = f1511.decide(cls)
        rows.append({
            "class": cls,
            "short": cls.rsplit(".", 1)[-1],
            "trigger": trigger,
            "cve": cve,
            "reachable_sink": sink,          # None if the method has no dangerous sink
            "present_in_jar": obj is not None,
            "decide_1411": d1411,            # deny | allow | unknown (unknown == not denied == passes a deny-list filter)
            "decide_1511": d1511,
        })
    shutil.rmtree(tmp, ignore_errors=True)

    evidence = {
        "generated": dt.datetime.now().strftime("%Y-%m-%d"),
        "coherence_jar": str(Path(args.coherence).name),
        "coherence_version": coherence_version(args.coherence),
        "filters": {
            "wl_1411": {"label": "WebLogic 14.1.1.0.0 GA", "note": "default serialFilter, blacklist-only, extracted from WebLogicFilterConfig (class dated 2020-03-16, pre April-2020 CPU)"},
            "wl_1511": {"label": "WebLogic 15.1.1.0.0", "note": "default serialFilter, current build"},
        },
        "legend": {
            "deny": "the filter rejects this class during resolveClass",
            "allow": "an explicit allow rule matches",
            "unknown": "no rule matches; under a blacklist-only filter the class is accepted (passes)",
        },
        "rows": rows,
        "notes": [
            "Verdicts are produced by tools.analysis.deserialization_filter.decide().",
            "reachable_sink is read from the jar by scan_rules.inventory, the Stage-1 bytecode reader.",
            "These are known, already-patched CVEs. This validates detection against ground truth; it is not a 0-day and does not demonstrate exploitation.",
        ],
    }
    Path(args.output).write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    # human-readable echo
    print(f"coherence {evidence['coherence_version']} | {len(rows)} gadget classes")
    print(f"{'class':<26}{'sink':<34}{'14.1.1':<9}{'15.1.1':<9}{'CVE'}")
    print("-" * 110)
    for r in rows:
        print(f"{r['short']:<26}{(r['reachable_sink'] or '-'):<34}{r['decide_1411']:<9}{r['decide_1511']:<9}{r['cve']}")
    print(f"\nwrote {args.output}")


if __name__ == "__main__":
    main()

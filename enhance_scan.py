#!/usr/bin/env python3
"""Create a separate, evidence-backed wrapper-enhanced scan preparation.

The original preparation and its scan results remain intact. This command never
executes target code or starts Flash; scan the new directory separately.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import zipfile

import yaml

from prepare_scan import validate_rule
from scan_rules.adaptive import collect_candidates, deterministic_proposals, request_proposals, validate_proposals
from scan_rules.gaps import gap_candidates, request_gap_proposals, validate_gap_proposals
from scan_rules.triage import load_catalog
from scan_rules.inventory import inventory
from scan_rules.summaries import VERSION, validator_identity


MODES = ("deterministic", "llm", "llm-gaps")


def enhance(prepared, output, *, mode="deterministic", model="gpt-4.1", max_methods=30, client=None):
    if mode not in MODES:
        raise ValueError("Enhancement mode must be deterministic, llm or llm-gaps.")
    source = Path(prepared).expanduser().resolve(strict=True)
    destination = Path(output).expanduser().absolute()
    if destination.exists() or destination.is_symlink():
        raise ValueError("Enhanced output already exists; choose a fresh directory.")
    config_raw = (source / "config.yml").read_bytes()
    knowledge_raw = (source / "knowledge.yml").read_bytes()
    config, knowledge = yaml.safe_load(config_raw), yaml.safe_load(knowledge_raw)
    manifest = json.loads((source / "manifest.json").read_text())
    if manifest.get("target_java") != 8 or manifest.get("enhancement"):
        raise ValueError("Use an original Java 8 preparation; chained enhancement is not supported.")
    target_paths = [Path(p).resolve(strict=True) for p in config["appClassPath"] + config["classPath"]]
    runtime_links = sorted((source / "java-benchmarks/JREs/jre1.8").glob("*.jar"))
    if not runtime_links:
        raise ValueError("Prepared runtime layout is missing.")
    classes = inventory([p.resolve(strict=True) for p in runtime_links])
    targets = inventory(target_paths, include_code=True)
    if classes.keys() & targets.keys():
        raise ValueError("Target/runtime classpath contains duplicate classes.")
    classes.update(targets)
    identity = hashlib.sha256(json.dumps(sorted((c.name, c.digest) for c in classes.values())).encode()).hexdigest()
    if identity != manifest["inventory_sha256"]:
        raise ValueError("Target bytecode changed since preparation; regenerate the baseline first.")
    methods = {m.signature: m for cls in classes.values() for m in cls.methods}
    request = None
    if mode == "llm-gaps":
        candidates = gap_candidates(manifest, classes, max_methods)
        effects = {effect["family"] for effect in load_catalog()["effects"]}
        proposals = {"proposals": []}
        if candidates:
            proposals, request = request_gap_proposals(candidates, effects, model=model, client=client)
        accepted, rejected = validate_gap_proposals(proposals, candidates, effects)
        occupied = {rule["method"] for section in knowledge.values() for rule in section}
        for entry in list(accepted):
            if entry["rule"]["method"] in occupied:
                accepted.remove(entry)
                rejected.append({"proposal": entry, "reason": "Method already has a built-in rule."})
                continue
            validate_rule(entry["section"], entry["rule"], methods[entry["rule"]["method"]])
            entry["class_sha256"] = classes[methods[entry["rule"]["method"]].owner].digest
            knowledge[entry["section"]].append(entry["rule"])
            occupied.add(entry["rule"]["method"])
        coverage = {"selected_gaps": len(candidates),
                    "unimplemented_total": manifest.get("coverage_gaps", {}).get("unimplemented_total", 0),
                    "selection": "abstract methods called by target code with no implementation on the classpath"}
    else:
        candidates, coverage = collect_candidates(targets, knowledge, max_methods)
        for candidate in candidates:
            if candidate["signature"] in config["sources"]:
                candidate["proof"].update(status="deferred", rules=[], reason="Protocol roots cannot be replaced by wrapper summaries.")
        if mode == "llm" and candidates:
            proposals, request = request_proposals(candidates, model=model, client=client)
        else:
            proposals = deterministic_proposals(candidates)
        accepted, rejected = validate_proposals(proposals, candidates)
        for entry in accepted:
            entry["section"] = "transfers"
            validate_rule("transfers", entry["rule"], methods[entry["rule"]["method"]])
            knowledge["transfers"].append(entry["rule"])
    report = {"schema_version": 1, "mode": mode, "validator": VERSION,
              "validator_sha256": validator_identity(),
              "baseline": str(source), "baseline_config_sha256": hashlib.sha256(config_raw).hexdigest(),
              "baseline_knowledge_sha256": hashlib.sha256(knowledge_raw).hexdigest(),
              "inventory_sha256": identity, "request": request, "coverage": coverage,
              "candidates": candidates, "proposals": proposals, "accepted": accepted, "rejected": rejected,
              "limitations": ["llm-gaps rules are unverified hypotheses: the methods have no implementation on the classpath."]
              if mode == "llm-gaps" else ["Proof is relative to reviewed baseline stream-constructor transfers.",
                              "Normal-return propagation does not prove callback reachability or exploitability.",
                              "No general control-flow, field/alias, guard or dynamic-dispatch inference.",
                              "LLM selection is experimental; no recall or speed advantage over deterministic inference is established.",
                              "Run baseline and enhanced scans separately; preserve the union of candidate evidence."]}
    owners = {methods[item["rule"]["method"]].owner for item in accepted}
    config["inputClasses"] = sorted(set(config["inputClasses"]) | owners)
    config["outputDir"] = str(destination / "output")
    config["analyses"]["method-summary"] = f"priori-knowledge:{destination / 'knowledge.yml'}"
    manifest["input_classes"] = config["inputClasses"]
    manifest["enhancement"] = {"mode": mode, "validator": VERSION, "baseline": str(source),
                               "validator_sha256": report["validator_sha256"],
                               "accepted_rules": len(accepted), "report": "enhancement.json"}
    if mode == "llm-gaps":
        manifest["enhancement"]["hypothesis_rules"] = [
            {"method": entry["rule"]["method"], "section": entry["section"], "effect": entry["effect"]} for entry in accepted]
    for index, entry in enumerate(accepted):
        method = methods[entry["rule"]["method"]]
        manifest["included_rules"].append({"rule": f"adaptive/{entry['section']}/{index}", "method": method.signature,
                                           "class_sha256": entry["class_sha256"], "origin": classes[method.owner].origin})
    manifest["limitations"].append(
        "Model-proposed gap rules are unverified hypotheses; triage labels every candidate that depends on one."
        if mode == "llm-gaps" else
        "Adaptive summaries have bounded validation; see enhancement.json for evidence and deferred methods.")
    destination.mkdir(parents=True)
    try:
        layout = destination / "java-benchmarks/JREs/jre1.8"
        layout.mkdir(parents=True)
        for link in runtime_links:
            (layout / link.name).symlink_to(link.resolve(strict=True))
        (destination / "config.yml").write_text(yaml.safe_dump(config, sort_keys=False))
        (destination / "knowledge.yml").write_text(yaml.safe_dump(knowledge, sort_keys=False))
        manifest["enhancement"]["config_sha256"] = hashlib.sha256((destination / "config.yml").read_bytes()).hexdigest()
        manifest["enhancement"]["knowledge_sha256"] = hashlib.sha256((destination / "knowledge.yml").read_bytes()).hexdigest()
        (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        (destination / "enhancement.json").write_text(json.dumps(report, indent=2) + "\n")
    except BaseException:
        shutil.rmtree(destination)
        raise
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared", required=True, help="Original prepare_scan.py output")
    parser.add_argument("--output", required=True, help="Fresh enhanced preparation directory")
    parser.add_argument("--mode", choices=MODES, default="deterministic",
                        help="llm-gaps: model proposes sinks/transfers for called abstract methods with no implementation")
    parser.add_argument("--model", default="gpt-4.1")
    parser.add_argument("--max-methods", type=int, default=30)
    args = parser.parse_args()
    try:
        report = enhance(args.prepared, args.output, mode=args.mode, model=args.model, max_methods=args.max_methods)
    except (ValueError, OSError, KeyError, zipfile.BadZipFile, yaml.YAMLError) as exc:
        parser.error(str(exc))
    kind = "hypothesis gap rules" if args.mode == "llm-gaps" else "wrapper transfers"
    print(f"Accepted {len(report['accepted'])} {kind}; rejected {len(report['rejected'])} proposals.")
    print(f"Evidence: {Path(args.output).absolute() / 'enhancement.json'}")
    print("Baseline preserved. Compare separately bounded baseline and enhanced scans; this is not a detection verdict.")


if __name__ == "__main__":
    main()

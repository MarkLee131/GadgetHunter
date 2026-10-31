#!/usr/bin/env python3
"""Prepare an experimental native-deserialization scan without handwritten YAML.

This command only reads class metadata and creates a new preparation directory.
It does not execute target code, invoke an LLM, or run Flash.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import zipfile
from pathlib import Path

import yaml

from scan_rules.archives import normalize
from scan_rules.boundaries import derive_stream_boundaries
from scan_rules.coverage import coverage_gaps, select_profiles, target_calls
from scan_rules.inventory import inventory, native_entries, proxy_entries
from scan_rules.purity import Checker, ignore_reason

ROOT = Path(__file__).resolve().parent
PROFILES = ("native-core", "jdk-propagation", "modern-effects", "reflection-dispatch", "reflection-boundaries", "property-access")
# Profiles whose transfers must be non-overridable; checked against the scanned classpath.
STRICT_TRANSFERS = ("jdk-propagation",)
SECTIONS = ("sinks", "transfers", "imitates", "ignores", "sanitizers")


def validate_rule(section, rule, method):
    """Reject malformed index references before the permissive backend sees them."""
    fields = {
        "sinks": {"method", "index"},
        "transfers": {"method", "from", "to"},
        "imitates": {"method", "action", "jump", "fromIdx", "recIdx", "paramIdx"},
        "ignores": {"method"},
    }
    if section not in fields or set(rule) - fields[section]:
        raise ValueError(f"Unsupported {section} rule: {rule}")

    def check(index, allow_result=False):
        if index == "base" and not method.static:
            return
        if index == "result" and allow_result and method.returns != "void":
            return
        if type(index) is int and 0 <= index < len(method.parameters):
            return
        raise ValueError(f"Invalid index {index!r}: {method.signature}")

    if section == "ignores":
        return  # safety is a classpath property; see scan_rules.purity.ignore_reason
    if section == "sinks":
        if not isinstance(rule.get("index"), list) or not rule["index"]:
            raise ValueError("Sink must identify controlled inputs")
        for index in rule["index"]:
            check(index)
    elif section == "transfers":
        check(rule.get("from"))
        check(rule.get("to"), allow_result=True)
    else:
        if rule.get("action") != "connect" or rule.get("jump") not in ("inference", "constructor"):
            raise ValueError("Unsupported dispatch approximation")
        for key in ("fromIdx", "paramIdx"):
            check(rule.get(key))
        if rule["jump"] == "inference":
            check(rule.get("recIdx"))


def compile_profiles(profiles, classes):
    methods = {m.signature: m for cls in classes.values() for m in cls.methods}
    compiled = {section: [] for section in SECTIONS}
    included, missing, digests = [], [], {}
    checker = None

    def refusal(profile, section, method):
        nonlocal checker
        if section == "ignores" or (section == "transfers" and profile in STRICT_TRANSFERS):
            checker = checker or Checker(classes)
            if section == "ignores":
                return ignore_reason(method, checker)
            if not checker.non_overridable(method):
                return "Overridable: a transfer would replace overriding gadget bodies."
        return None
    for profile in profiles:
        if profile not in PROFILES:
            raise ValueError(f"Unknown built-in profile: {profile}")
        path = ROOT / "rules" / f"{profile}.yml"
        raw = path.read_bytes()
        digests[profile] = hashlib.sha256(raw).hexdigest()
        document = yaml.safe_load(raw)
        if set(document) != set(SECTIONS) or any(not isinstance(document[k], list) for k in SECTIONS):
            raise ValueError(f"Invalid profile structure: {profile}")
        for section in SECTIONS:
            for number, rule in enumerate(document[section]):
                rule_id = f"{profile}/{section}/{number}"
                signature = rule["method"]
                if signature not in methods:
                    missing.append({"rule": rule_id, "method": signature})
                    continue
                validate_rule(section, rule, methods[signature])
                if reason := refusal(profile, section, methods[signature]):
                    missing.append({"rule": rule_id, "method": signature, "reason": reason})
                    continue
                if rule not in compiled[section]:
                    compiled[section].append(rule)
                owner = classes[methods[signature].owner]
                included.append({"rule": rule_id, "method": signature,
                                 "class_sha256": owner.digest, "origin": owner.origin})
    if checker:
        checker.close()
    if not compiled["sinks"]:
        raise ValueError("No resolved sink methods; include native-core and the target Java 8 runtime")
    sinks = {rule["method"] for rule in compiled["sinks"]}
    overrides = {rule["method"] for section in ("transfers", "imitates") for rule in compiled[section]}
    if shadowed := sinks & overrides:
        raise ValueError("Flash handles transfers/dispatch before sinks; overlapping rules would suppress boundaries: "
                         + ", ".join(sorted(shadowed)))
    if hidden := {rule["method"] for rule in compiled["ignores"]} & (sinks | overrides):
        raise ValueError("Ignored methods cannot also be sinks or transfers: " + ", ".join(sorted(hidden)))
    return compiled, included, missing, digests


def runtime_version(runtime_dir):
    """Read the target runtime's version from rt.jar without executing it."""
    try:
        with zipfile.ZipFile(runtime_dir / "rt.jar") as archive:
            for line in archive.read("META-INF/MANIFEST.MF").decode("utf-8", "replace").splitlines():
                if line.startswith("Implementation-Version:"):
                    return line.split(":", 1)[1].strip()
    except (OSError, KeyError, zipfile.BadZipFile):
        pass
    return None


def prepare(apps, libraries, java_home, output, profiles, proxy_roots_enabled=False):
    apps = [Path(p).expanduser().resolve(strict=True) for p in apps]
    libraries = [Path(p).expanduser().resolve(strict=True) for p in libraries]
    java_home = Path(java_home).expanduser().resolve(strict=True)
    runtime_dir = java_home / "jre" / "lib"
    if not runtime_dir.is_dir():
        runtime_dir = java_home / "lib"
    if not (runtime_dir / "rt.jar").is_file():
        raise ValueError("--java8-home must contain jre/lib/rt.jar or lib/rt.jar; modular JDKs are not supported yet")
    runtime = sorted(runtime_dir.glob("*.jar"))
    paths = runtime + apps + libraries
    if len(set(paths)) != len(paths):
        raise ValueError("Repeated classpath entries")
    output = Path(output).expanduser().absolute()
    if output.exists() or output.is_symlink():
        raise ValueError(f"Output already exists; choose a fresh directory: {output}")
    output.mkdir(parents=True, exist_ok=False)
    try:
        return prepare_into(output, apps, libraries, runtime, runtime_dir, java_home, profiles, proxy_roots_enabled)
    except BaseException:
        shutil.rmtree(output)
        raise


def prepare_into(output, apps, libraries, runtime, runtime_dir, java_home, profiles, proxy_roots_enabled=False):
    # Fat JAR, WAR and multi-release inputs become ordinary JARs under output/classpath.
    apps, libraries, archives = normalize(apps, libraries, runtime, output / "classpath")
    classes = inventory(runtime)
    targets = inventory(apps + libraries, include_code=True)
    classes.update(targets)
    calls, callers = target_calls(targets)
    selection = None
    if profiles in (None, ["auto"]):
        profiles, selection = select_profiles(calls)
    app_class_count = sum(any(item.origin.startswith(str(path) + ("/" if path.is_dir() else "!")) for path in apps)
                          for item in classes.values())
    if not app_class_count:
        raise ValueError("Application classpath contains no Java classes")
    compiled, included, missing, digests = compile_profiles(profiles, classes)
    # Helpers that open a deserialization stream over a parameter become boundaries.
    occupied = {rule["method"] for section in compiled.values() for rule in section}
    methods = {m.signature: m for cls in targets.values() for m in cls.methods}
    derived = derive_stream_boundaries(targets, occupied)
    for number, rule in enumerate(derived):
        method = methods[rule["method"]]
        validate_rule("sinks", rule, method)
        compiled["sinks"].append(rule)
        included.append({"rule": f"derived/sinks/{number}", "method": rule["method"],
                         "class_sha256": targets[method.owner].digest, "origin": targets[method.owner].origin})
    gaps = coverage_gaps(calls, callers, classes, {rule["method"] for section in compiled.values() for rule in section})
    entries = native_entries(classes)
    proxy_roots = proxy_entries(classes) if proxy_roots_enabled else []
    entries = sorted(set(entries) | set(proxy_roots))
    # Flash resolves knowledge against its loaded world, not every class on disk.
    # Seed owners explicitly so unused library sinks/callbacks are not silently skipped.
    input_classes = sorted({item["method"][1:].split(":", 1)[0] for item in included}
                           | {entry[1:].split(":", 1)[0] for entry in entries})
    unresolved = sorted({name for cls in classes.values() for name in (cls.parent, *cls.interfaces)
                         if name and name not in classes})
    manifest = {
        "schema_version": 1, "status": "prepared-not-scanned", "protocol": "jdk-native",
        "target_java": 8, "target_runtime_version": runtime_version(runtime_dir), "java_home": str(java_home), "profiles": digests,
        "backend_sha256": hashlib.sha256((ROOT / "multi-agents/flash/flash.jar").read_bytes()).hexdigest(),
        "class_count": len(classes), "application_class_count": app_class_count,
        "inventory_sha256": hashlib.sha256(json.dumps(sorted((c.name, c.digest) for c in classes.values())).encode()).hexdigest(),
        "entries": entries, "proxy_roots": proxy_roots, "input_classes": input_classes,
        "included_rules": included, "unresolved_rules": missing,
        "unresolved_hierarchy_types": unresolved,
        "classpath_normalization": archives,
        "profile_selection": selection or {name: "requested" for name in profiles},
        "coverage_gaps": gaps,
        "derived_boundaries": [{"method": rule["method"], "index": rule["index"], "effect": "secondary-deserialization",
                                "evidence": "parameter passed into new ObjectInputStream"} for rule in derived],
        "limitations": [
            "Experimental Java 8 native profile; metadata resolution is not a data-flow correctness proof.",
            "This baseline has no adaptive rules; framework boundary, guard and exploit verification are not implemented.",
            "Receiver summaries are coarse; ProcessBuilder state and nested reads need path-specific review.",
            "Missing method bodies, unresolved types and Flash budget exhaustion can reduce coverage.",
            "Runtime extension JARs are not added automatically; pass required extensions using --lib.",
        ],
    }
    if archives["dropped_newer_bytecode"]:
        manifest["limitations"].append(f"{archives['dropped_newer_bytecode']} classes need a newer runtime than Java 8 and were not scanned.")
    if archives["shadowed_duplicates"]:
        manifest["limitations"].append(f"{archives['shadowed_duplicates']} duplicate classes were shadowed by an earlier classpath entry.")
    if 'reflection-boundaries' in profiles:
        manifest['limitations'].append(
            'Reflection boundaries track coarse Method/Constructor selection taint, not callable-target or effect proof. '
            'Fixed reflective targets with controlled invocation arguments are outside this profile; '
            'Object.getClass receiver taint can overapproximate actual type control.')
    config = {
        "classPath": [str(p) for p in libraries], "appClassPath": [str(p) for p in apps],
        "inputClasses": input_classes, "javaVersion": 8, "prependJVM": False, "allowPhantom": True,
        "worldBuilderClass": "pascal.taie.frontend.soot.SootWorldBuilder",
        "outputDir": str(output / "output"), "preBuildIR": False, "worldCacheMode": False,
        "scope": "ALL", "nativeModel": True, "planFile": None,
        "sources": entries,
        # Helper objects created during callbacks need not themselves be Serializable.
        "filterNonSerializable": False, "GC_MAX_LEN": 25,
        "analyses": {"method-summary": f"priori-knowledge:{output / 'knowledge.yml'}"},
        "GC_OUT": "chains", "COLLECT_GC_INPROCESS": False, "GCGraph_COLLECT_TIME": 10,
        "SINK_MAX_TIME": 180, "LCS_THRESHOLD": 0.8, "onlyGenPlan": False,
        "keepResult": ["$KEEP-ALL"],
    }
    # Flash locates its target runtime relative to the configuration's directory.
    runtime_layout = output / "java-benchmarks/JREs/jre1.8"
    runtime_layout.mkdir(parents=True)
    for jar in runtime:
        (runtime_layout / jar.name).symlink_to(jar)
    (output / "knowledge.yml").write_text(yaml.safe_dump(compiled, sort_keys=False), encoding="utf-8")
    (output / "config.yml").write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", action="append", required=True, help="Application JAR or class directory; repeatable")
    parser.add_argument("--lib", action="append", default=[], help="Dependency JAR or class directory; repeatable")
    parser.add_argument("--java8-home", required=True, help="Java 8 target runtime (separate from the JVM running Flash)")
    parser.add_argument("--output", required=True, help="New preparation directory")
    parser.add_argument("--proxy-roots", action="store_true", help="Add Serializable InvocationHandler.invoke methods as dynamic-proxy dispatch roots (experimental)")
    parser.add_argument("--profile", action="append", choices=("auto", *PROFILES),
                        help="Repeatable; default 'auto' selects profiles from the target bytecode")
    args = parser.parse_args()
    try:
        manifest = prepare(args.app, args.lib, args.java8_home, args.output, args.profile or ["auto"], args.proxy_roots)
    except (ValueError, OSError, KeyError, IndexError, TypeError, UnicodeError, zipfile.BadZipFile, yaml.YAMLError) as exc:
        parser.error(str(exc))
    print(f"Prepared {len(manifest['entries'])} callback candidates, {len(manifest['included_rules'])} resolved rules.")
    print("Profiles: " + ", ".join(f"{k} ({v})" for k, v in manifest["profile_selection"].items()))
    print(f"Unresolved rules: {len(manifest['unresolved_rules'])}; hierarchy types: {len(manifest['unresolved_hierarchy_types'])}.")
    gaps = manifest["coverage_gaps"]
    if gaps["missing_classes"]:
        print(f"{gaps['missing_classes']} referenced classes are not on the classpath; most calls go to "
              + ", ".join(p["package"] for p in gaps["missing_packages"][:5]) + ". Add those JARs with --lib.")
    if gaps["unimplemented_total"]:
        print(f"{gaps['unimplemented_total']} called abstract methods have no implementation on the classpath; "
              "enhance_scan.py --mode llm-gaps can propose their semantics.")
    normalization = manifest["classpath_normalization"]
    if dropped := normalization["dropped_newer_bytecode"] + normalization["shadowed_duplicates"]:
        print(f"Classpath normalization skipped {dropped} classes (newer bytecode or shadowed duplicates); see manifest.")
    print(f"Review {Path(args.output).absolute() / 'manifest.json'}; this is not a scan result.")


if __name__ == "__main__":
    main()

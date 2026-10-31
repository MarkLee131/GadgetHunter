"""Rank candidate chains for review by novelty, effect and scanned-build mitigations.

Labels are review aids. Nothing is deleted: a mitigation lowers priority and
explains why, and "novel" only means no catalogued public family matched.
Mitigation evidence is read from the scanned bytecode where the catalog allows.
"""
from __future__ import annotations

import hashlib
import json
import re
import zipfile
from pathlib import Path

import yaml

from scan_rules.inventory import inventory, invoked_methods, is_subtype, load_class

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "rules" / "triage.yml"
SIGNATURE = re.compile(r"<([\w.$]+): (\S+) ([^\s(]+)\(([^)]*)\)>")
EDGE = re.compile(r"\[(\w+)\] (<.+?>) --\(.*?\)--> (<.+>)")
CALLBACKS = ("readObject", "readObjectNoData", "readResolve", "readExternal")
IMPLAUSIBLE_RECEIVERS = 3
RUNTIME_PREFIXES = ("java.", "javax.", "sun.", "com.sun.", "jdk.", "org.w3c.", "org.xml.", "org.ietf.", "org.omg.")


def runtime_version(text):
    """'1.8.0_432' or '8u432' -> (8, 432); '17.0.9' -> (17, 9). None if unknown."""
    if not text:
        return None
    if match := re.fullmatch(r"(?:1\.)?(\d+)(?:\.\d+)*(?:_(\d+))?(?:-.*)?|(\d+)u(\d+)", str(text).strip()):
        if match.group(3):
            return int(match.group(3)), int(match.group(4))
        feature = int(match.group(1))
        if match.group(2):
            return feature, int(match.group(2))
        parts = str(text).split("-")[0].split(".")
        return feature, int(parts[2]) if feature > 8 and len(parts) > 2 and parts[2].isdigit() else 0
    return None


def parse_chain(chain):
    """Return ordered methods [(owner, name, signature)] for one candidate block."""
    methods = []
    for edge in chain:
        if not (match := EDGE.fullmatch(edge.strip())):
            raise ValueError(f"Malformed candidate edge: {edge[:120]}")
        for signature in match.group(2, 3):
            if not (parts := SIGNATURE.fullmatch(signature)):
                raise ValueError(f"Malformed method signature: {signature[:120]}")
            item = (parts.group(1), parts.group(3), signature)
            if not methods or methods[-1] != item:
                methods.append(item)
    return methods


def load_catalog(path=CATALOG):
    raw = Path(path).read_bytes()
    catalog = yaml.safe_load(raw)
    if catalog.get("schema_version") != 1 or not all(isinstance(catalog.get(k), list)
                                                      for k in ("effects", "families", "mitigations")):
        raise ValueError(f"Invalid triage catalog: {path}")
    catalog["sha256"] = hashlib.sha256(raw).hexdigest()
    catalog["effect_index"] = {key: effect for effect in catalog["effects"] for key in effect["methods"]}
    return catalog


def class_matches(owner, keys):
    return any(owner.startswith(key) if key.endswith(".") else owner == key for key in keys or ())


class Facts:
    """Lazy bytecode facts about classes on the scanned classpath."""

    def __init__(self, classes=None):
        self.classes, self.archives, self.cache = classes, {}, {}

    def full(self, name):
        if self.classes is None or name not in self.classes:
            return None
        if name not in self.cache:
            self.cache[name] = load_class(self.classes[name].origin, archives=self.archives)
        return self.cache[name]

    def calls(self, owner, method, target):
        """True/False from bytecode; None when the class is not available."""
        cls = self.full(owner)
        if cls is None:
            return None
        target_owner, _, target_name = target.rpartition(".")
        return any((call[0], call[1]) == (target_owner, target_name)
                   for item in cls.methods if item.name == method and item.code
                   for call in invoked_methods(item.code))

    def constructs_stream(self, owner, method):
        """Whether a body creates any ObjectInputStream; None when unknown."""
        cls = self.full(owner)
        if cls is None:
            return None
        return any(call[1] == "<init>" and is_subtype(call[0], "java.io.ObjectInputStream", self.classes)
                   for item in cls.methods if item.name == method and item.code
                   for call in invoked_methods(item.code))

    def serializable(self, name):
        if self.classes is None or name not in self.classes:
            return None
        return is_subtype(name, "java.io.Serializable", self.classes)

    def static(self, owner, method):
        """True only when every same-named declaration is static."""
        if self.classes is None or owner not in self.classes:
            return False
        found = [item for item in self.classes[owner].methods if item.name == method]
        return bool(found) and all(item.static for item in found)

    def declares(self, owner, method):
        if self.classes is None or owner not in self.classes:
            return None
        return any(item.name == method for item in self.classes[owner].methods)

    def runtime_class(self, name, runtime_origins):
        if runtime_origins and self.classes is not None and name in self.classes:
            return self.classes[name].origin.split("!", 1)[0] in runtime_origins
        return name.startswith(RUNTIME_PREFIXES)

    def close(self):
        for archive in self.archives.values():
            archive.close()


def mitigation_hits(methods, effect, catalog, facts, runtime):
    hits = []
    pairs = list(zip(methods, methods[1:]))
    for rule in catalog["mitigations"]:
        when, evidence = rule["when"], rule["evidence"]
        matched = []
        if "edge_from" in when:
            if any(f"{a[0]}.{a[1]}" == when["edge_from"] and b[1] == when["edge_to_name"]
                   and b[0] not in when.get("edge_to_not", ()) for a, b in pairs):
                matched = [when["edge_from"].rpartition(".")[0]]
        if when.get("methods") and any(f"{m[0]}.{m[1]}" in when["methods"] for m in methods):
            matched = [m[0] for m in methods if f"{m[0]}.{m[1]}" in when["methods"]]
        if when.get("classes"):
            matched = sorted({m[0] for m in methods if class_matches(m[0], when["classes"])})
        if when.get("effects") and effect in when["effects"]:
            matched = ["<effect>"]
        if not matched:
            continue
        state = None
        if "calls" in evidence:
            owner, _, name = evidence["calls"]["method"].rpartition(".")
            state = facts.calls(owner, name, evidence["calls"]["target"])
        elif "callback_calls" in evidence:
            states = [any(facts.calls(owner, callback, evidence["callback_calls"]) or False for callback in CALLBACKS)
                      if facts.full(owner) is not None else None for owner in matched]
            state = True if True in states else (None if None in states else False)
        elif "not_serializable" in evidence:
            states = [None if facts.serializable(owner) is None else not facts.serializable(owner) for owner in matched]
            state = True if True in states else (None if None in states else False)
        elif "declares" in evidence:
            owner, _, name = evidence["declares"].rpartition(".")
            state = facts.declares(owner, name)
        elif "runtime_since" in evidence:
            since = runtime_version(evidence["runtime_since"])
            state = None if runtime is None else runtime >= since if runtime[0] == since[0] else runtime[0] > since[0]
        if state is False:
            continue
        hits.append({"id": rule["id"], "status": rule["status"] if state else "unverified",
                     "summary": rule["summary"], "source": rule.get("source")})
    return hits


def triage_chain(chain, catalog, facts, runtime, runtime_origins=frozenset(), hypotheses=None, derived=None):
    methods = parse_chain(chain)
    sink = methods[-1]
    effect = catalog["effect_index"].get(f"{sink[0]}.{sink[1]}")
    derived = derived or {}
    hypotheses = hypotheses or {}
    if sink[2] in derived:
        effect = next((e for e in catalog["effects"] if e["family"] == derived[sink[2]]), effect)
    if sink[2] in hypotheses and hypotheses[sink[2]].get("effect"):
        family = hypotheses[sink[2]]["effect"]
        effect = next((e for e in catalog["effects"] if e["family"] == family), effect)
    owners = [m[0] for m in methods]
    keys = {f"{m[0]}.{m[1]}" for m in methods}
    known, triggers, terminals = [], set(), set()
    for family in catalog["families"]:
        if any(class_matches(o, family.get("core")) for o in owners) or keys & set(family.get("core_methods", ())):
            known.append(family["id"])
        triggers |= {o for o in owners if class_matches(o, family.get("trigger"))}
        terminals |= {o for o in owners if class_matches(o, family.get("terminal"))}
    family_name = effect["family"] if effect else "unclassified"
    priority = effect["priority"] if effect else 0
    streams = ("java.io.ObjectInputStream", "java.io.ObjectInput")
    if (family_name == "secondary-deserialization" and sink[0] in streams
            and all(set(streams) & set(SIGNATURE.fullmatch(m[2]).group(4).split(",")) for m in methods[:-1])
            and all(facts.constructs_stream(m[0], m[1]) is False for m in methods[:-1])):
        # Every caller only has the original stream and builds no new one: the
        # callback reads its own fields/elements under the original filter.
        family_name, priority = "stream-continuation", -1
    hits = mitigation_hits(methods, family_name, catalog, facts, runtime)
    for method in dict.fromkeys(m[2] for m in methods if m[2] in hypotheses):
        rule = hypotheses[method]
        hits.append({"id": "llm-hypothesis", "status": "constrained", "source": None,
                     "summary": f"Relies on a model-proposed {rule['section'][:-1]} rule for {method}; "
                                "no implementation on the classpath could verify it."})
    outside = list(dict.fromkeys(o for o in owners if not facts.runtime_class(o, runtime_origins)))
    # Receivers the stream cannot supply must come from earlier callback code.
    # Common in real chains (iterators, helpers), so this only breaks ties.
    unserializable = sorted({m[0] for m in methods[1:] if m[1] not in ("<init>", "<clinit>")
                             and facts.serializable(m[0]) is False and not facts.static(m[0], m[1])})
    return {
        "novelty": "known" if known else "novel",
        "families": known, "triggers": sorted(triggers), "terminals": sorted(terminals),
        "effect": family_name, "priority": priority,
        "sink": sink[2], "entry": methods[0][2],
        "mitigations": hits,
        "blocked": any(h["status"] == "blocked" for h in hits),
        "constrained": any(h["status"] in ("constrained", "unverified") for h in hits),
        "runtime_only": not outside, "non_runtime_classes": outside,
        "unserializable_receivers": unserializable,
        # Three or more stream-independent receivers is rarely attacker-controlled.
        "implausible": len(unserializable) >= IMPLAUSIBLE_RECEIVERS,
        "route": [m[2] for m in methods[1:]],
        "edge_count": len(chain),
    }


def review_key(item):
    # Unblocked chains through target classes first, then new before known,
    # high-impact effects, plausibility tie-breakers, short chains.
    return (item["blocked"], item["priority"] < 0, item["runtime_only"], item["implausible"], item["novelty"] == "known",
            -item["priority"], item["constrained"],
            len(item["unserializable_receivers"]), item["edge_count"], item["chain_id"])


def triage_chains(chains, *, catalog=None, classes=None, runtime=None, runtime_origins=frozenset(), hypotheses=None, derived=None):
    catalog = catalog or load_catalog()
    facts = Facts(classes)
    hypotheses = {rule["method"]: rule for rule in hypotheses or ()}
    derived = {rule["method"]: rule["effect"] for rule in derived or ()}
    try:
        items = [dict(chain_id=index, **triage_chain(chain, catalog, facts, runtime_version(runtime), runtime_origins,
                                                     hypotheses, derived))
                 for index, chain in enumerate(chains)]
    finally:
        facts.close()
    clusters = {}
    for item in sorted(items, key=review_key):
        # Same target classes and effect: one review unit. Runtime-only chains
        # group by the route after the entry callback, which many callbacks share.
        key = (tuple(item["non_runtime_classes"]) or ("runtime", *item.pop("route")), item["effect"])
        item.pop("route", None)
        cluster = clusters.setdefault(key, {"cluster_id": len(clusters), "representative": item["chain_id"], "members": []})
        cluster["members"].append(item["chain_id"])
        item["cluster_id"] = cluster["cluster_id"]
    for rank, item in enumerate(sorted(items, key=review_key)):
        item["rank"] = rank
    summary = {"candidates": len(items), "clusters": len(clusters),
               "novel": sum(i["novelty"] == "novel" for i in items),
               "known": sum(i["novelty"] == "known" for i in items),
               "blocked": sum(i["blocked"] for i in items),
               "novel_unblocked": sum(i["novelty"] == "novel" and not i["blocked"] for i in items),
               "target_unblocked": sum(not i["runtime_only"] and not i["blocked"] for i in items),
               "target_clusters": len({i["cluster_id"] for i in items if not i["runtime_only"]}),
               "by_effect": {}, "by_family": {}}
    for item in items:
        summary["by_effect"][item["effect"]] = summary["by_effect"].get(item["effect"], 0) + 1
        for family in item["families"]:
            summary["by_family"][family] = summary["by_family"].get(family, 0) + 1
    return {"schema_version": 1, "catalog_sha256": catalog["sha256"], "runtime": runtime,
            "summary": summary, "candidates": items, "clusters": list(clusters.values())}


def runtime_from_manifest(manifest):
    return manifest.get("target_runtime_version")


def triage_prepared(folder, chains_file=None, output=None, hypotheses=None):
    """Triage a prepared scan's candidates and write ranked review files.

    hypotheses: model-proposed rules (from an llm-gaps manifest) that candidates may rely on.
    """
    from scan_rules.runner import read_candidates
    folder = Path(folder)
    manifest = json.loads((folder / "manifest.json").read_text())
    config = yaml.safe_load((folder / "config.yml").read_text())
    runtime_jars = sorted((folder / "java-benchmarks/JREs/jre1.8").glob("*.jar"))
    paths = [p.resolve() for p in runtime_jars] + [Path(p) for p in config["classPath"] + config["appClassPath"]]
    try:
        classes = inventory(paths)
    except (ValueError, OSError, zipfile.BadZipFile):
        classes = None  # facts become "unverified" rather than guessed
    parsed = read_candidates(Path(chains_file) if chains_file else folder / "chains")
    hypotheses = list(hypotheses or ()) + manifest.get("enhancement", {}).get("hypothesis_rules", [])
    report = triage_chains(parsed["chains"], classes=classes, runtime=runtime_from_manifest(manifest),
                           runtime_origins=frozenset(str(p.resolve()) for p in runtime_jars), hypotheses=hypotheses,
                           derived=manifest.get("derived_boundaries"))
    report["class_facts"] = "checked" if classes is not None else "unavailable"
    write_review(output or folder, parsed["chains"], report)
    return report


def write_review(folder, chains, report):
    from scan_rules.runner import atomic_report
    folder = Path(folder)
    ordered = sorted(report["candidates"], key=lambda i: i["rank"])
    (folder / "chains.ranked").write_text("".join("\n".join(chains[i["chain_id"]]) + "\n\n" for i in ordered), encoding="utf-8")
    representatives = [c["representative"] for c in report["clusters"]]
    (folder / "chains.review").write_text("".join("\n".join(chains[i]) + "\n\n" for i in representatives), encoding="utf-8")
    report["files"] = {"ranked": str(folder / "chains.ranked"), "review": str(folder / "chains.review"),
                       "review_order": representatives}
    atomic_report(folder / "triage.json", report)

"""Stitch native-callback prefixes to dynamic-proxy handler fragments.

A java.lang.reflect.Proxy built during deserialization dispatches every interface
call to its handler's invoke, but the backend cannot synthesize that dispatch edge
(a stream-built proxy has no points-to target). A scan prepared with --proxy-roots
emits the two halves separately: native-callback chains (readObject -> ... -> a call
on a controllable object that could be a proxy) and handler fragments
(InvocationHandler.invoke -> ... -> sink). This module reconnects them the way JDD
models dynamic proxies at the gadget-chain level: where a native chain calls an
interface method, or a reflective-invocation facade, on an attacker-controllable
receiver, that receiver can be a proxy whose handler is any Serializable handler.

The link is permissive (the attacker chooses the handler), so the output is ranked
review leads, not proven chains: richer prefixes reaching higher-value sinks first.
Controllability is read from the backend's own edge annotation, so a call on a
not-controllable receiver is never a stitch point.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

EDGE = re.compile(r"\[(\w+)\] <([^>]+)> --\(line:(-?\d+), constraint:\[([^\]]*)\]\)--> <([^>]+)>")
# ContrUtil: -1 = this, -2 = polluted (both attacker-controllable); -3 = not polluted; >=0 = caller param index.
CONTROLLABLE = {"-1", "-2"}
JDK = ("java.", "javax.", "jdk.")

# Reflective-invocation facades: the invoked object runs a chosen method, so it can be a proxy.
REFLECT_SINKS = (
    "java.lang.reflect.Method: java.lang.Object invoke",
    "java.lang.reflect.Constructor: java.lang.Object newInstance",
    "org.apache.commons.beanutils.PropertyUtils: java.lang.Object getProperty",
    "org.apache.commons.beanutils.PropertyUtils: java.lang.Object getSimpleProperty",
    "org.apache.commons.beanutils.PropertyUtils: java.lang.Object getNestedProperty",
    "org.apache.commons.beanutils.PropertyUtilsBean: java.lang.Object getProperty",
    "org.apache.commons.beanutils.PropertyUtilsBean: java.lang.Object getSimpleProperty",
    "org.apache.commons.beanutils.PropertyUtilsBean: java.lang.Object getNestedProperty",
)
# Sink -> review priority (3 highest), matching the triage effect order.
DANGER = {
    "java.lang.reflect.Method: java.lang.Object invoke": 3,
    "java.lang.reflect.Constructor: java.lang.Object newInstance": 3,
    "java.lang.Runtime: java.lang.Process exec": 3,
    "java.lang.ProcessBuilder: java.lang.Process start": 3,
    "defineClass": 3,
    "javax.naming.Context: java.lang.Object lookup": 2,
    "javax.naming.InitialContext: java.lang.Object lookup": 2,
}


def _owner(signature):
    return signature.split(":", 1)[0]


def _method(signature):
    match = re.match(r"[^:]+:\s*(?:\S+\s+)?([\w<>$]+)\(", signature)
    return match.group(1) if match else signature.rpartition(" ")[2].split("(")[0]


def _sink_priority(block):
    for key, priority in DANGER.items():
        if key in block:
            return priority
    return 0


def _core(edges):
    """Library/application gadget methods in a prefix (drops JDK plumbing)."""
    core = []
    seen = set()
    for _kind, caller, _line, _contr, callee in edges:
        for signature in (caller, callee):
            owner = _owner(signature)
            token = f"{owner}.{_method(signature)}"
            if not owner.startswith(JDK) and token not in seen:
                seen.add(token)
                core.append(token)
    return core


def load(scan_dir):
    """Split a --proxy-roots scan into native-callback chains and handler fragments."""
    scan_dir = Path(scan_dir)
    manifest = json.loads((scan_dir / "manifest.json").read_text())
    roots = {root.strip("<>") for root in manifest.get("proxy_roots", [])}
    if not roots:
        raise ValueError("Scan has no proxy_roots; prepare with --proxy-roots first.")
    native, fragments = [], []
    for block in (scan_dir / "chains").read_text(errors="replace").strip().split("\n\n"):
        edges = [match.groups() for match in EDGE.finditer(block)]
        if not edges:
            continue
        head = edges[0][1]
        (fragments if head in roots else native).append((block, edges))
    return native, fragments, roots


def _join_points(native, root_owners):
    """Prefix truncated where it calls, on a controllable receiver, an interface method or a
    reflective facade whose target could be a proxy. Yields (prefix_edges, owner, method)."""
    for _block, edges in native:
        for index, (kind, _caller, _line, contr, callee) in enumerate(edges):
            owner = _owner(callee)
            if owner in root_owners:
                continue  # an already-resolved proxy handler, not a fresh injection point
            values = [value.strip() for value in contr.split(",") if value.strip()]
            receiver_controllable = bool(values) and values[0] in CONTROLLABLE
            is_interface = kind == "INTERFACE"
            is_reflect = index == len(edges) - 1 and any(callee.startswith(sink) for sink in REFLECT_SINKS)
            if (is_interface or is_reflect) and receiver_controllable:
                prefix = edges[: index + 1]
                if len(_core(prefix)) >= 2:  # require real gadget content before the proxy
                    yield prefix, owner, _method(callee)


def stitch(scan_dir, cap=500, fragments_per_prefix=8):
    """Ranked proxy-stitch leads reconnecting prefixes to Serializable-handler fragments."""
    native, fragments, roots = load(scan_dir)
    root_owners = {_owner(root) for root in roots}
    # Keep the shortest fragment per (handler, sink) that reaches a high-value sink.
    best_fragment = {}
    for block, edges in fragments:
        priority = _sink_priority(block)
        if priority == 0:
            continue
        key = (edges[0][1], edges[-1][4])
        if key not in best_fragment or len(edges) < len(best_fragment[key][0]):
            best_fragment[key] = (edges, priority)
    ranked_fragments = sorted(best_fragment.values(), key=lambda item: (-item[1], len(item[0])))
    # Keep the shortest prefix per (gadget set, interface owner, method).
    best_prefix = {}
    for prefix, owner, method in _join_points(native, root_owners):
        key = (frozenset(_core(prefix)), owner, method)
        if key not in best_prefix or len(prefix) < len(best_prefix[key]):
            best_prefix[key] = prefix
    leads = []
    for (core, owner, method), prefix in best_prefix.items():
        for fragment_edges, priority in ranked_fragments[:fragments_per_prefix]:
            leads.append({
                "priority": priority,
                "inject_at": f"{owner}.{method}",
                "handler": fragment_edges[0][1],
                "sink": fragment_edges[-1][4],
                "prefix_gadgets": sorted(core),
                "prefix_len": len(prefix),
            })
    leads.sort(key=lambda lead: (-lead["priority"], -len(lead["prefix_gadgets"]), lead["prefix_len"]))
    return leads[:cap], len(best_prefix), len(best_fragment)

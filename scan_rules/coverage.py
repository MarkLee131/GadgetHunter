"""Target-derived configuration: profile selection and coverage gaps.

Both read the application and library bytecode only; nothing is executed.
"""
from __future__ import annotations

from collections import Counter

from scan_rules.inventory import invoked_methods, descriptor_types

AUTO_BASE = ("native-core", "jdk-propagation", "modern-effects")
REFLECTION_CALLS = {("java.lang.reflect.Method", "invoke"), ("java.lang.reflect.Constructor", "newInstance")}
PROPERTY_FACADES = {
    ("org.apache.commons.beanutils.PropertyUtils", "getProperty"),
    ("org.apache.commons.beanutils.PropertyUtils", "getSimpleProperty"),
    ("org.apache.commons.beanutils.PropertyUtils", "getNestedProperty"),
    ("org.apache.commons.beanutils.PropertyUtils", "getIndexedProperty"),
    ("org.apache.commons.beanutils.BeanUtils", "getProperty"),
    ("org.apache.commons.beanutils.PropertyUtilsBean", "getProperty"),
    ("org.apache.commons.beanutils.PropertyUtilsBean", "getSimpleProperty"),
    ("org.apache.commons.beanutils.PropertyUtilsBean", "getNestedProperty"),
}


def target_calls(targets):
    """Counter of (owner, name, descriptor) -> call sites, plus callers per target."""
    calls, callers = Counter(), {}
    for cls in targets.values():
        for method in cls.methods:
            if method.code is None:
                continue
            for target in invoked_methods(method.code):
                calls[target] += 1
                callers.setdefault(target, set()).add(method.signature)
    return calls, callers


def select_profiles(calls):
    """Recommended profiles, with the reason for each optional one."""
    profiles, reasons = list(AUTO_BASE), {name: "default" for name in AUTO_BASE}
    reflective = sum(count for (owner, name, _), count in calls.items() if (owner, name) in REFLECTION_CALLS)
    if reflective:
        profiles.append("reflection-boundaries")
        reasons["reflection-boundaries"] = f"{reflective} reflective invocation sites in application/library code"
    facades = sum(count for (owner, name, _), count in calls.items() if (owner, name) in PROPERTY_FACADES)
    if facades:
        profiles.append("property-access")
        reasons["property-access"] = f"{facades} Commons Beanutils property-access sites in application/library code"
    return profiles, reasons


def implemented(name, method_name, returns, parameters, classes, children):
    pending, seen = [name], set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        cls = classes.get(current)
        if cls and any(m.name == method_name and m.returns == returns and m.parameters == parameters
                       and not m.flags & 0x0400 for m in cls.methods):
            return True
        pending.extend(children.get(current, ()))
    return False


def coverage_gaps(calls, callers, classes, covered, limit=40):
    """Calls the search cannot follow: absent classes and bodiless abstract methods."""
    children = {}
    for cls in classes.values():
        for parent in (cls.parent, *cls.interfaces):
            if parent:
                children.setdefault(parent, []).append(cls.name)
    missing, unimplemented = Counter(), []
    for (owner, name, descriptor), count in calls.items():
        if owner not in classes:
            if not owner.startswith("["):
                missing[owner] += count
            continue
        returns, parameters = descriptor_types(descriptor)
        method = next((m for m in classes[owner].methods if m.name == name and m.parameters == parameters
                       and m.returns == returns), None)
        if method is None or not method.flags & 0x0400 or method.signature in covered:
            continue
        if implemented(owner, name, returns, parameters, classes, children):
            continue
        unimplemented.append({"method": method.signature, "call_sites": count,
                              "callers": sorted(callers[(owner, name, descriptor)])[:5]})
    packages = Counter()
    for owner, count in missing.items():
        packages[".".join(owner.split(".")[:-1][:3]) or owner] += count
    unimplemented.sort(key=lambda item: (-item["call_sites"], item["method"]))
    return {"missing_classes": len(missing),
            "missing_packages": [{"package": p, "call_sites": c} for p, c in packages.most_common(15)],
            "unimplemented_methods": unimplemented[:limit],
            "unimplemented_total": len(unimplemented)}

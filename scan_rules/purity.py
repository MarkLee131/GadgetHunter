"""Closed-world checks that let predefined ignores and transfers be applied safely.

Flash skips an ignored callee entirely (no taint side effects, no call edge) and
replaces a transferred callee's body. A wrong rule therefore hides real chains.
These checks run over the whole scanned classpath, which is everything an
attacker can place in a native stream.
"""
from __future__ import annotations

from scan_rules.inventory import descriptor_types, instructions, load_class, operand_reference

PRIMITIVES = ("int", "long", "double", "float", "boolean", "byte", "char", "short")
MAX_DEPTH = 8
MAX_TARGETS = 16


class Checker:
    def __init__(self, classes):
        self.classes, self.archives, self.full, self.memo = classes, {}, {}, {}
        self.children = {}
        for cls in classes.values():
            for parent in (cls.parent, *cls.interfaces):
                if parent:
                    self.children.setdefault(parent, []).append(cls.name)

    def close(self):
        for archive in self.archives.values():
            archive.close()

    def body(self, owner, method):
        if owner not in self.full:
            self.full[owner] = load_class(self.classes[owner].origin, archives=self.archives)
        return next(m for m in self.full[owner].methods if m.name == method.name
                    and m.parameters == method.parameters and m.returns == method.returns)

    def subtypes(self, name):
        pending, seen = list(self.children.get(name, ())), set()
        while pending:
            current = pending.pop()
            if current not in seen:
                seen.add(current)
                pending.extend(self.children.get(current, ()))
        return seen

    def declared(self, owner, name, returns, parameters):
        cls = self.classes.get(owner)
        return cls and next((m for m in cls.methods if m.name == name and m.returns == returns
                             and m.parameters == parameters), None)

    def resolve(self, owner, name, returns, parameters):
        """Nearest declaration in the superclass chain, as the JVM resolves it."""
        current = owner
        while current in self.classes:
            if found := self.declared(current, name, returns, parameters):
                return current, found
            current = self.classes[current].parent
        return None

    def non_overridable(self, method):
        """A call to this method always runs this exact body."""
        cls = self.classes[method.owner]
        if method.static or method.name == "<init>" or method.flags & (0x0002 | 0x0010) or cls.flags & 0x0010:
            return True
        overrides = [sub for sub in self.subtypes(method.owner)
                     if self.declared(sub, method.name, method.returns, method.parameters)]
        sealed = not any(m.name == "<init>" and not m.flags & 0x0002 for m in cls.methods)
        return sealed and not overrides

    def targets(self, owner, name, returns, parameters, opcode):
        """Every body an invoke instruction can run, or None if unbounded/unknown."""
        if opcode in (0xb7, 0xb8):  # special/static: exact
            found = self.resolve(owner, name, returns, parameters)
            return [found] if found else None
        found = [] if self.classes.get(owner, None) is None else [self.resolve(owner, name, returns, parameters)]
        if not found or found[0] is None and opcode == 0xb6:
            return None
        found = [f for f in found if f]
        for sub in self.subtypes(owner):
            if method := self.declared(sub, name, returns, parameters):
                found.append((sub, method))
        return found if 0 < len(found) <= MAX_TARGETS else None

    def leaf(self, owner, method, depth=0):
        """True when the body cannot run user code or move references elsewhere."""
        key = method.signature
        if key in self.memo:
            return self.memo[key]
        self.memo[key] = True  # recursion assumes success; any failure overwrites it
        result = self._leaf(owner, method, depth)
        self.memo[key] = result
        return result

    def _leaf(self, owner, method, depth):
        if depth > MAX_DEPTH:
            return False
        if method.flags & 0x0100:  # native: only when no reference arguments can be called back
            return all(p in PRIMITIVES for p in method.parameters)
        if method.flags & 0x0400:
            return False
        code = self.body(owner, method).code
        if code is None:
            return False
        for offset, opcode in instructions(code):
            if opcode in (0x53, 0xba):  # aastore, invokedynamic
                return False
            if opcode in (0xb3, 0xb5):  # putstatic/putfield: primitive state only
                reference = operand_reference(code, offset)
                if reference is None or reference[2][0] in "L[":
                    return False
            if opcode in (0xb6, 0xb7, 0xb8, 0xb9):
                reference = operand_reference(code, offset)
                if reference is None:
                    return False
                target_owner, name, descriptor = reference
                returns, parameters = descriptor_types(descriptor)
                if name == "<init>" and self.throwable(target_owner):
                    continue  # the exact exception type is fixed by the bytecode
                found = self.targets(target_owner, name, returns, parameters, opcode)
                if found is None or not all(self.leaf(o, m, depth + 1) for o, m in found):
                    return False
        return True

    def throwable(self, name):
        current = name
        while current in self.classes:
            if current == "java.lang.Throwable":
                return True
            current = self.classes[current].parent
        return False


def ignore_reason(method, checker):
    """None when an ignore rule is safe; otherwise why it was refused."""
    if method.returns not in PRIMITIVES:
        return "Ignored calls must return a primitive; a reference result could carry taint."
    if not checker.non_overridable(method):
        return "Overridable: another class on the classpath could run user code here."
    if not checker.leaf(method.owner, method):
        return "Body can reach overridable code, invokedynamic or reference state."
    return None

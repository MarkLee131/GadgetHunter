"""Derive secondary-deserialization boundaries from target bytecode.

The backend reports `new ObjectInputStream(controlled)` when the stream is built
in a callback, but not when a helper builds it from its own parameter (a
`deserialize(InputStream)` or `fromBytes(byte[])` wrapper). This module finds
such helpers by exact instruction patterns and turns them into boundary sinks on
that parameter. A parameter slot that is ever reassigned is not trusted.
"""
from __future__ import annotations

from scan_rules.inventory import instructions, operand_reference

OIS = ("java.io.ObjectInputStream", "<init>", "(Ljava/io/InputStream;)V")
# Constructors that wrap their first argument without changing whose bytes are read.
WRAPPERS = {
    ("java.io.ByteArrayInputStream", "<init>", "([B)V"),
    ("java.io.BufferedInputStream", "<init>", "(Ljava/io/InputStream;)V"),
    ("java.io.DataInputStream", "<init>", "(Ljava/io/InputStream;)V"),
    ("java.util.zip.GZIPInputStream", "<init>", "(Ljava/io/InputStream;)V"),
    ("java.util.zip.InflaterInputStream", "<init>", "(Ljava/io/InputStream;)V"),
}
LOADS = {0x2a: 0, 0x2b: 1, 0x2c: 2, 0x2d: 3}
STORES = {0x4b: 0, 0x4c: 1, 0x4d: 2, 0x4e: 3}
CATEGORY2 = ("long", "double")


def parameter_slots(method):
    slot, slots = (0 if method.static else 1), {}
    for index, kind in enumerate(method.parameters):
        slots[slot] = index
        slot += 2 if kind in CATEGORY2 else 1
    return slots


def loaded_slot(code, offset, opcode):
    if opcode in LOADS:
        return LOADS[opcode]
    if opcode == 0x19:  # aload index
        return code.bytecode[offset + 1]
    return None


def stream_parameters(method):
    """Parameter indices passed (directly or via a wrapper) into new ObjectInputStream."""
    code = method.code
    if code is None:
        return set()
    decoded = list(instructions(code))
    stored = {STORES[op] if op in STORES else code.bytecode[off + 1]
              for off, op in decoded if op in STORES or op == 0x3a}
    slots = parameter_slots(method)
    found = set()
    for position, (offset, opcode) in enumerate(decoded):
        if opcode != 0xb7 or operand_reference(code, offset) != OIS:
            continue
        previous = decoded[position - 1] if position >= 1 else None
        slot = loaded_slot(code, *previous) if previous else None
        if slot is None and position >= 2 and decoded[position - 1][1] == 0xb7 \
                and operand_reference(code, decoded[position - 1][0]) in WRAPPERS:
            slot = loaded_slot(code, *decoded[position - 2])  # new W; dup; aload p; W.<init>; OIS.<init>
        if slot in slots and slot not in stored:
            found.add(slots[slot])
    return found


def derive_stream_boundaries(targets, occupied):
    """Sink rules for helpers that open a deserialization stream over a parameter."""
    rules = []
    for cls in targets.values():
        for method in cls.methods:
            if method.signature in occupied or method.name.startswith("<"):
                continue
            for index in sorted(stream_parameters(method)):
                rules.append({"method": method.signature, "index": [index]})
    return rules

"""Small, fail-closed wrapper verifier relative to reviewed baseline semantics.

This is not a general JVM interpreter. Unsupported instructions, dispatch and
effects defer a method instead of manufacturing a whole-method transfer rule.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import struct

from scan_rules.inventory import descriptor_types

VERSION = "straight-line-streams-v1"
STREAM_CONSTRUCTORS = {
    "<java.io.ByteArrayInputStream: void <init>(byte[])>",
    "<java.io.ByteArrayInputStream: void <init>(byte[],int,int)>",
    "<java.io.ObjectInputStream: void <init>(java.io.InputStream)>",
}


def validator_identity():
    root = Path(__file__).resolve().parents[1]
    digest = hashlib.sha256()
    for name in ("scan_rules/inventory.py", "scan_rules/summaries.py", "scan_rules/adaptive.py", "enhance_scan.py"):
        digest.update(name.encode() + b"\0" + (root / name).read_bytes() + b"\0")
    return digest.hexdigest()


class Deferred(ValueError):
    pass


@dataclass
class Value:
    sources: set = field(default_factory=set)
    allocated: str | None = None
    initialized: bool = True
    reference: bool = True


def inspect_method(method, owner, knowledge):
    """Prove all normal-return provenance while ruling out unmodeled effects.

    Constructor composition uses exactly the existing baseline transfer for an
    exact new stream object; it does not assert that constructors are pure in Java.
    No arbitrary virtual call, field write, branch or exception handler is erased.
    """
    body = method.code
    result = {"method": method.signature, "class_sha256": owner.digest,
              "body_sha256": hashlib.sha256(body.bytecode).hexdigest() if body else None,
              "validator": VERSION, "status": "deferred", "rules": [], "trace": []}
    try:
        if body is None:
            raise Deferred("No bytecode body (native, abstract, or omitted).")
        if method.flags & (0x0100 | 0x0400 | 0x0020):
            raise Deferred("Native, abstract or synchronized method.")
        if not (method.static or method.flags & (0x0002 | 0x0010) or owner.flags & 0x0010):
            raise Deferred("Overridable instance dispatch cannot be replaced by a method-wide rule.")
        if method.name.startswith("<") or method.returns in ("void", "int", "long", "double", "float", "boolean", "byte", "char", "short"):
            raise Deferred("Only ordinary reference-returning wrappers are supported.")
        occupied = {r["method"] for section in knowledge.values() for r in section}
        if method.signature in occupied:
            raise Deferred("Already modeled by a baseline rule.")
        if body.handlers:
            raise Deferred("Exception handlers require control-flow validation.")
        if len(body.bytecode) > 2048:
            raise Deferred("Method exceeds the verifier's bytecode budget.")
        stack, locals_ = [], {}
        slot = 0
        if not method.static:
            locals_[0] = Value({"base"})
            slot = 1
        for index, kind in enumerate(method.parameters):
            locals_[slot] = Value({index}, reference=kind not in ("int", "long", "double", "float", "boolean", "byte", "char", "short"))
            slot += 2 if kind in ("long", "double") else 1
        offset, steps = 0, 0
        code = body.bytecode

        def operand(size):
            nonlocal offset
            if offset + size > len(code):
                raise Deferred("Truncated instruction.")
            value = int.from_bytes(code[offset:offset + size], "big")
            offset += size
            return value

        def pop():
            if not stack:
                raise Deferred("Invalid operand stack.")
            return stack.pop()

        while offset < len(code):
            pc = offset
            opcode = operand(1)
            steps += 1
            if steps > 256:
                raise Deferred("Instruction budget exceeded.")
            event = {"offset": pc, "opcode": f"{opcode:02x}"}
            result["trace"].append(event)
            if opcode == 0x00:  # nop
                continue
            if 0x01 <= opcode <= 0x08:  # null / integer constants
                stack.append(Value(reference=opcode == 0x01))
            elif opcode in (0x10, 0x11):  # integer immediates
                operand(2 if opcode == 0x11 else 1)
                stack.append(Value(reference=False))
            elif opcode in (0x15, 0x19) or 0x1a <= opcode <= 0x1d or 0x2a <= opcode <= 0x2d:
                index = operand(1) if opcode in (0x15, 0x19) else opcode - (0x1a if opcode <= 0x1d else 0x2a)
                if index not in locals_:
                    raise Deferred("Load from an unknown local.")
                if locals_[index].reference != (opcode == 0x19 or 0x2a <= opcode <= 0x2d):
                    raise Deferred("Local load has an incompatible value category.")
                stack.append(locals_[index])
                event["local"] = index
            elif opcode in (0x36, 0x3a) or 0x3b <= opcode <= 0x3e or 0x4b <= opcode <= 0x4e:
                index = operand(1) if opcode in (0x36, 0x3a) else opcode - (0x3b if opcode <= 0x3e else 0x4b)
                if index >= body.max_locals:
                    raise Deferred("Store exceeds local-variable table.")
                value = pop()
                if value.reference != (opcode == 0x3a or 0x4b <= opcode <= 0x4e):
                    raise Deferred("Local store has an incompatible value category.")
                locals_[index] = value
                event["local"] = index
            elif opcode == 0x59:  # dup; references and category-1 values only
                value = pop()
                stack.extend((value, value))
            elif opcode == 0x57:
                pop()
            elif opcode == 0xbb:  # new: exact type, no virtual constructor dispatch
                target = body.classes.get(operand(2))
                if target not in ("java.io.ByteArrayInputStream", "java.io.ObjectInputStream"):
                    raise Deferred("Allocation outside the reviewed stream summaries.")
                event["class"] = target
                stack.append(Value(allocated=target, initialized=False))
            elif opcode == 0xb7:  # invokespecial: reviewed exact constructors only
                reference = body.references.get(operand(2))
                if reference is None:
                    raise Deferred("Unresolved invocation.")
                target, name, descriptor = reference
                returns, parameters = descriptor_types(descriptor)
                signature = f"<{target}: {returns} {name}({','.join(parameters)})>"
                event["callee"] = signature
                if signature not in STREAM_CONSTRUCTORS:
                    raise Deferred("Invocation is not a reviewed stream constructor.")
                if any(r["method"] == signature for key in ("sinks", "imitates", "ignores", "sanitizers") for r in knowledge[key]):
                    raise Deferred("Constructor has a conflicting baseline role.")
                rules = [r for r in knowledge["transfers"] if r["method"] == signature]
                if rules != [{"method": signature, "from": 0, "to": "base"}]:
                    raise Deferred("Constructor baseline differs from the reviewed contract.")
                event["baseline_transfer"] = {"from": 0, "to": "base"}
                arguments = [pop() for _ in parameters][::-1]
                receiver = pop()
                if receiver.allocated != target or receiver.initialized:
                    raise Deferred("Constructor receiver is not an exact fresh allocation.")
                if not arguments or not all(v.initialized for v in arguments):
                    raise Deferred("Uninitialized constructor input.")
                if any(v.reference != (kind not in ("int", "long", "double", "float", "boolean", "byte", "char", "short"))
                       for v, kind in zip(arguments, parameters)):
                    raise Deferred("Constructor input has an incompatible value category.")
                receiver.sources.update(arguments[0].sources)
                receiver.initialized = True
            elif opcode == 0xc0:  # checkcast preserves identity on normal return
                target = body.classes.get(operand(2))
                if target is None or not stack or not stack[-1].reference:
                    raise Deferred("Invalid cast.")
                event["class"] = target
            elif opcode == 0xb0:
                value = pop()
                if offset != len(code) or stack or not value.initialized or not value.reference:
                    raise Deferred("Return does not terminate a valid straight-line body.")
                result["rules"] = [{"method": method.signature, "from": source, "to": "result"}
                                   for source in sorted(value.sources, key=str)]
                result.update(status="verified" if result["rules"] else "no-flow",
                              reason="Complete straight-line normal-return provenance under reviewed baseline contracts.")
                return result
            else:
                raise Deferred(f"Unsupported instruction 0x{opcode:02x} at {pc}; method body remains unanalyzed.")
        raise Deferred("No supported reference return.")
    except (Deferred, IndexError, struct.error) as exc:
        result.update(reason=str(exc), rules=[])
        return result

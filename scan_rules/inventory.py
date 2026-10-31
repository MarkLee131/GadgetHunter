"""Read Java class metadata without loading or executing target classes."""
from __future__ import annotations

import hashlib
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Code:
    bytecode: bytes
    max_locals: int
    handlers: int
    # Constant-pool references are resolved once; targets are never loaded.
    references: dict[int, tuple[str, str, str]]
    classes: dict[int, str]


@dataclass(frozen=True)
class Method:
    owner: str
    name: str
    returns: str
    parameters: tuple[str, ...]
    flags: int
    code: Code | None = None

    @property
    def signature(self):
        return f"<{self.owner}: {self.returns} {self.name}({','.join(self.parameters)})>"

    @property
    def static(self):
        return bool(self.flags & 0x0008)


@dataclass(frozen=True)
class JavaClass:
    name: str
    parent: str | None
    interfaces: tuple[str, ...]
    methods: tuple[Method, ...]
    flags: int
    major: int
    origin: str
    digest: str


def descriptor_types(descriptor):
    """Decode a JVM method descriptor, including arrays and primitive types."""
    primitives = dict(B="byte", C="char", D="double", F="float", I="int",
                      J="long", S="short", Z="boolean", V="void")
    offset = 0

    def one(allow_void=False):
        nonlocal offset
        dimensions = 0
        while offset < len(descriptor) and descriptor[offset] == "[":
            dimensions += 1
            offset += 1
        if offset >= len(descriptor):
            raise ValueError("Truncated method descriptor")
        code = descriptor[offset]
        offset += 1
        if code == "L":
            end = descriptor.find(";", offset)
            if end <= offset:
                raise ValueError("Invalid reference descriptor")
            value = descriptor[offset:end].replace("/", ".")
            offset = end + 1
        elif code in primitives and (code != "V" or allow_void and not dimensions):
            value = primitives[code]
        else:
            raise ValueError(f"Invalid descriptor type: {code}")
        return value + "[]" * dimensions

    if not descriptor.startswith("("):
        raise ValueError("Expected method descriptor")
    offset = 1
    parameters = []
    while offset < len(descriptor) and descriptor[offset] != ")":
        parameters.append(one())
    if offset == len(descriptor):
        raise ValueError("Missing descriptor return type")
    offset += 1
    returns = one(allow_void=True)
    if offset != len(descriptor):
        raise ValueError("Trailing method descriptor data")
    return returns, tuple(parameters)


def read_class(data: bytes, origin: str, include_code=False) -> JavaClass:
    offset = 0

    def take(size):
        nonlocal offset
        end = offset + size
        if end > len(data):
            raise ValueError(f"Truncated class: {origin}")
        result = data[offset:end]
        offset = end
        return result

    def number(fmt):
        return struct.unpack(fmt, take(struct.calcsize(fmt)))[0]

    def u2():
        return number(">H")

    def attributes():
        result = {}
        for _ in range(u2()):
            name = pool[u2()]
            value = take(number(">I"))
            if name in result:
                raise ValueError(f"Duplicate attribute {name}: {origin}")
            result[name] = value
        return result

    if take(4) != b"\xca\xfe\xba\xbe":
        raise ValueError(f"Invalid class header: {origin}")
    u2()  # minor version
    major = u2()
    pool = [None] * u2()
    index = 1
    while index < len(pool):
        tag = number(">B")
        if tag == 1:
            # JVM strings use modified UTF-8. Names/descriptors normally use ASCII;
            # surrogatepass also preserves encoded UTF-16 surrogate pairs.
            pool[index] = take(u2()).replace(b"\xc0\x80", b"\x00").decode("utf-8", "surrogatepass")
        elif tag == 7:
            pool[index] = u2()
        elif tag in (8, 16, 19, 20):
            take(2)
        elif tag in (9, 10, 11, 12):
            pool[index] = (tag, u2(), u2())
        elif tag in (3, 4, 17, 18):
            take(4)
        elif tag in (5, 6):
            take(8)
            index += 1
        elif tag == 15:
            take(3)
        else:
            raise ValueError(f"Unsupported constant-pool tag {tag}: {origin}")
        index += 1

    def class_name(index):
        return pool[pool[index]].replace("/", ".") if index else None

    references, class_refs = {}, {}
    if include_code:
        for index, value in enumerate(pool):
            if type(value) is int:
                class_refs[index] = class_name(index)
            elif isinstance(value, tuple) and value[0] in (9, 10, 11):
                _, owner, pair = value
                _, member, descriptor = pool[pair]
                references[index] = (class_name(owner), pool[member], pool[descriptor])

    flags = u2()
    name, parent = class_name(u2()), class_name(u2())
    interfaces = tuple(class_name(u2()) for _ in range(u2()))
    for _ in range(u2()):  # fields
        take(6)
        attributes()
    methods = []
    for _ in range(u2()):
        method_flags, method_name, descriptor = u2(), pool[u2()], pool[u2()]
        returns, parameters = descriptor_types(descriptor)
        attrs = attributes()
        code = None
        if include_code and "Code" in attrs:
            body = attrs["Code"]
            if len(body) < 10:
                raise ValueError(f"Truncated Code attribute: {origin}")
            _, locals_count, length = struct.unpack_from(">HHI", body)
            if length > 65535 or len(body) < 10 + length:
                raise ValueError(f"Invalid Code length: {origin}")
            handlers = struct.unpack_from(">H", body, 8 + length)[0]
            if len(body) < 12 + length + handlers * 8:
                raise ValueError(f"Truncated exception table: {origin}")
            code = Code(body[8:8 + length], locals_count, handlers, references, class_refs)
        methods.append(Method(name, method_name, returns, parameters, method_flags, code))
    attributes()
    if offset != len(data):
        raise ValueError(f"Trailing class data: {origin}")
    return JavaClass(name, parent, interfaces, tuple(methods), flags, major,
                     origin, hashlib.sha256(data).hexdigest())


def inventory(paths: list[Path], max_bytes=512 * 1024 * 1024, include_code=False):
    """Index ordinary JARs/class directories; reject ambiguous classpaths."""
    classes = {}
    consumed = 0

    def add(data, origin):
        nonlocal consumed
        consumed += len(data)
        if consumed > max_bytes:
            raise ValueError("Class inventory exceeds 512 MiB")
        item = read_class(data, origin, include_code=include_code)
        if item.major > 52:
            raise ValueError(f"Initial native profile supports Java 8 bytecode only: {origin}")
        if item.name in classes:
            raise ValueError(f"Duplicate class {item.name}: {classes[item.name].origin}; {origin}")
        classes[item.name] = item

    for path in paths:
        if path.is_dir():
            for file in sorted(path.rglob("*.class")):
                if file.stat().st_size > 16 * 1024 * 1024:
                    raise ValueError(f"Class exceeds 16 MiB: {file}")
                add(file.read_bytes(), str(file))
        else:
            with zipfile.ZipFile(path) as archive:
                entries = archive.infolist()
                if any(e.filename.startswith(("BOOT-INF/", "WEB-INF/", "META-INF/versions/")) for e in entries):
                    raise ValueError(f"Unpack fat/WAR/multi-release archives into ordinary classpath entries first: {path}")
                for entry in sorted(entries, key=lambda e: e.filename):
                    if entry.filename.endswith(".jar"):
                        raise ValueError(f"Nested JAR requires an explicit classpath entry: {path}!{entry.filename}")
                    if not entry.filename.endswith(".class"):
                        continue
                    if entry.file_size > 16 * 1024 * 1024 or consumed + entry.file_size > max_bytes:
                        raise ValueError(f"Class inventory size limit: {path}!{entry.filename}")
                    add(archive.read(entry), f"{path}!{entry.filename}")
    return classes


def is_subtype(name, expected, classes):
    pending, seen = [name], set()
    while pending:
        current = pending.pop()
        if current == expected:
            return True
        if current in seen or current not in classes:
            continue
        seen.add(current)
        item = classes[current]
        pending.extend(item.interfaces)
        if item.parent:
            pending.append(item.parent)
    return False


def native_entries(classes):
    """Select declared callback candidates; reachability still needs validation."""
    entries = []
    for cls in classes.values():
        if cls.flags & (0x0200 | 0x4000) or not is_subtype(cls.name, "java.io.Serializable", classes):
            continue  # interfaces and enums do not supply these native callbacks
        for method in cls.methods:
            if method.static or method.flags & 0x0400:
                continue
            private = bool(method.flags & 0x0002)
            hook = (method.name in ("readObject", "readObjectNoData") and private
                    and method.returns == "void"
                    and method.parameters == (("java.io.ObjectInputStream",) if method.name == "readObject" else ()))
            external = (method.name == "readExternal" and method.flags & 0x0001
                        and method.returns == "void" and method.parameters == ("java.io.ObjectInput",)
                        and is_subtype(cls.name, "java.io.Externalizable", classes))
            resolve = method.name == "readResolve" and method.returns == "java.lang.Object" and not method.parameters
            # Runs after the graph is restored for any object passed to registerValidation.
            validation = (method.name == "validateObject" and method.flags & 0x0001 and method.returns == "void"
                          and not method.parameters and is_subtype(cls.name, "java.io.ObjectInputValidation", classes))
            if hook or external or resolve or validation:
                entries.append(method.signature)
    return sorted(entries)


def proxy_entries(classes):
    """Serializable InvocationHandler.invoke methods: dynamic-proxy dispatch roots.

    A java.lang.reflect.Proxy built during deserialization dispatches every
    interface call to its handler's invoke. The backend does not synthesize that
    dispatch edge (a stream-built proxy has no points-to target), so these handlers
    are invisible as search roots. Treating invoke as an additional callback lets
    the backend emit handler-to-sink fragments for stitching, the way JDD models
    dynamic proxies at the gadget-chain level. The handler's own fields (this) are
    the attacker-controlled state, exactly like a native readObject callback.
    """
    entries = []
    for cls in classes.values():
        if cls.flags & (0x0200 | 0x4000):
            continue  # interfaces and enums do not supply a concrete handler
        if not (is_subtype(cls.name, "java.lang.reflect.InvocationHandler", classes)
                and is_subtype(cls.name, "java.io.Serializable", classes)):
            continue
        for method in cls.methods:
            if (method.name == "invoke" and not method.static and method.returns == "java.lang.Object"
                    and method.parameters == ("java.lang.Object", "java.lang.reflect.Method", "java.lang.Object[]")):
                entries.append(method.signature)
    return sorted(entries)


def instructions(code: Code):
    """Yield (offset, opcode) for each instruction, decoding operand lengths."""
    data, offset = code.bytecode, 0
    fixed = {0x10: 2, 0x12: 2, 0x84: 3, 0xa9: 2, 0xbc: 2, 0xc5: 4, 0xb9: 5, 0xba: 5, 0xc8: 5, 0xc9: 5}
    fixed.update({op: 2 for op in range(0x15, 0x1a)})
    fixed.update({op: 2 for op in range(0x36, 0x3b)})
    fixed.update({op: 3 for op in (0x11, 0x13, 0x14, 0xbb, 0xbd, 0xc0, 0xc1, 0xc6, 0xc7, *range(0x99, 0xa9), *range(0xb2, 0xb9))})
    while offset < len(data):
        opcode = data[offset]
        yield offset, opcode
        if opcode in (0xaa, 0xab):  # switches are 4-byte aligned from the body start
            cursor = offset + 1 + (-(offset + 1) % 4)
            if opcode == 0xaa:
                low, high = struct.unpack_from(">ii", data, cursor + 4)
                if high < low:
                    raise ValueError("Invalid tableswitch range")
                offset = cursor + 12 + 4 * (high - low + 1)
            else:
                pairs = struct.unpack_from(">i", data, cursor + 4)[0]
                if pairs < 0:
                    raise ValueError("Invalid lookupswitch size")
                offset = cursor + 8 + 8 * pairs
        elif opcode == 0xc4:  # wide
            offset += 6 if offset + 1 < len(data) and data[offset + 1] == 0x84 else 4
        else:
            offset += fixed.get(opcode, 1)
    if offset != len(data):
        raise ValueError("Instruction stream overruns its body")


def operand_reference(code: Code, offset):
    """Constant-pool member reference used by the instruction at offset."""
    if offset + 3 > len(code.bytecode):
        raise ValueError("Truncated instruction")
    return code.references.get(int.from_bytes(code.bytecode[offset + 1:offset + 3], "big"))


def invoked_methods(code: Code):
    """Return (owner, name, descriptor) for every invoke instruction in one body.

    Decodes instruction boundaries so operand bytes are never read as opcodes.
    invokedynamic call sites are not resolved and are omitted.
    """
    return {target for offset, opcode in instructions(code) if opcode in (0xb6, 0xb7, 0xb8, 0xb9)
            and (target := operand_reference(code, offset)) is not None}


def load_class(origin: str, include_code=True, archives=None) -> JavaClass:
    """Re-read one inventoried class from its recorded origin.

    Pass a dict as ``archives`` to reuse open JARs; the caller closes them.
    """
    archive, separator, entry = origin.partition("!")
    if not separator:
        return read_class(Path(origin).read_bytes(), origin, include_code=include_code)
    if archives is None:
        with zipfile.ZipFile(archive) as stream:
            return read_class(stream.read(entry), origin, include_code=include_code)
    if archive not in archives:
        archives[archive] = zipfile.ZipFile(archive)
    return read_class(archives[archive].read(entry), origin, include_code=include_code)

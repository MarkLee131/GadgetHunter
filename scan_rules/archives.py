"""Turn real-world deliverables into an unambiguous Java 8 classpath.

Spring Boot JARs and WARs are split into application classes and nested
libraries. Entries a Java 8 runtime cannot load (multi-release overlays,
module-info, bytecode newer than 52) are dropped, and duplicate classes keep
the first definition in classpath order, as the JVM does. Every change is
recorded so the manifest shows what was not scanned.
"""
from __future__ import annotations

import io
import re
import zipfile
from pathlib import Path

MAX_ENTRY = 64 * 1024 * 1024
MAX_NESTED = 256 * 1024 * 1024
MAX_TOTAL = 2 * 1024 * 1024 * 1024
LAYOUTS = (("spring-boot", "BOOT-INF/classes/", "BOOT-INF/lib/"), ("war", "WEB-INF/classes/", "WEB-INF/lib/"))


class Budget:
    def __init__(self):
        self.used = 0

    def take(self, size, label):
        self.used += size
        if self.used > MAX_TOTAL:
            raise ValueError(f"Archive expansion exceeds 2 GiB: {label}")


def class_name(entry):
    return entry[:-len(".class")].replace("/", ".")


def runtime_names(runtime_jars):
    names = set()
    for jar in runtime_jars:
        with zipfile.ZipFile(jar) as archive:
            names.update(class_name(e) for e in archive.namelist() if e.endswith(".class"))
    return names


def safe_stem(name, index):
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", Path(name).name)[:80] or "archive.jar"
    return f"{index:04d}-{stem if stem.endswith('.jar') else stem + '.jar'}"


class Normalizer:
    def __init__(self, workdir, defined):
        self.workdir, self.defined, self.budget = Path(workdir), set(defined), Budget()
        self.counter = 0
        self.report = {"archives": [], "dropped_newer_bytecode": 0, "dropped_multi_release": 0,
                       "dropped_module_info": 0, "shadowed_duplicates": 0, "shadowed_examples": [],
                       "newer_bytecode_examples": []}

    def write(self, label, entries):
        """entries: iterable of (name, bytes) for class files; returns a path or None."""
        kept = []
        for name, data in entries:
            if name.endswith("module-info.class"):
                self.report["dropped_module_info"] += 1
                continue
            if len(data) < 8 or data[:4] != b"\xca\xfe\xba\xbe":
                raise ValueError(f"Invalid class header: {label}!{name}")
            if int.from_bytes(data[6:8], "big") > 52:
                self.report["dropped_newer_bytecode"] += 1
                if len(self.report["newer_bytecode_examples"]) < 10:
                    self.report["newer_bytecode_examples"].append(f"{label}!{name}")
                continue
            qualified = class_name(name)
            if qualified in self.defined:
                self.report["shadowed_duplicates"] += 1
                if len(self.report["shadowed_examples"]) < 10:
                    self.report["shadowed_examples"].append(f"{label}!{name}")
                continue
            self.defined.add(qualified)
            kept.append((name, data))
        if not kept:
            return None
        self.workdir.mkdir(parents=True, exist_ok=True)
        path = self.workdir / safe_stem(label, self.counter)
        self.counter += 1
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as out:
            for name, data in kept:
                out.writestr(name, data)
        return path

    def expand(self, archive, label, role, depth=0):
        """Return [(role, path)] for one opened archive."""
        names = archive.infolist()
        layout = next((item for item in LAYOUTS if any(e.filename.startswith(item[1]) for e in names)), None)
        results, classes, nested = [], [], []
        for entry in sorted(names, key=lambda e: e.filename):
            name = entry.filename
            if entry.is_dir():
                continue
            if name.startswith("META-INF/versions/"):
                if name.endswith(".class"):
                    self.report["dropped_multi_release"] += 1
                continue
            if name.endswith(".jar"):
                nested.append(entry)
            elif name.endswith(".class"):
                if entry.file_size > MAX_ENTRY:
                    raise ValueError(f"Class exceeds 64 MiB: {label}!{name}")
                if layout:
                    if not name.startswith(layout[1]):
                        continue  # launcher or container classes, not the application
                    name = name[len(layout[1]):]
                self.budget.take(entry.file_size, label)
                classes.append((name, archive.read(entry)))
        kind = layout[0] if layout else "jar"
        if path := self.write(label, classes):
            results.append((role, path))
        for entry in nested:
            if depth >= 2:
                raise ValueError(f"Nested archives deeper than two levels: {label}!{entry.filename}")
            if entry.file_size > MAX_NESTED:
                raise ValueError(f"Nested JAR exceeds 256 MiB: {label}!{entry.filename}")
            self.budget.take(entry.file_size, label)
            with zipfile.ZipFile(io.BytesIO(archive.read(entry))) as inner:
                results.extend(self.expand(inner, f"{label}!{entry.filename}", "library", depth + 1))
        self.report["archives"].append({"input": label, "kind": kind, "role": role,
                                        "nested_jars": len(nested), "classes_written": len(classes)})
        return results

    def plain(self, archive):
        """True when the JAR can be passed through unchanged."""
        for entry in archive.infolist():
            name = entry.filename
            if name.startswith(("BOOT-INF/", "WEB-INF/", "META-INF/versions/")) or name.endswith((".jar", "module-info.class")):
                return False
            if name.endswith(".class"):
                with archive.open(entry) as stream:
                    header = stream.read(8)
                if len(header) == 8 and int.from_bytes(header[6:8], "big") > 52 or class_name(name) in self.defined:
                    return False
        return True

    def add(self, path, role):
        path = Path(path)
        if path.is_dir():
            self.defined.update(class_name(str(f.relative_to(path))) for f in path.rglob("*.class"))
            return [(role, path)]
        with zipfile.ZipFile(path) as archive:
            if self.plain(archive):
                self.defined.update(class_name(e) for e in archive.namelist() if e.endswith(".class"))
                self.report["archives"].append({"input": str(path), "kind": "jar", "role": role, "unchanged": True})
                return [(role, path)]
            return self.expand(archive, str(path), role)


def normalize(apps, libraries, runtime_jars, workdir):
    """Return (apps, libraries, report) with only Java 8-loadable, unique classes."""
    normalizer = Normalizer(workdir, runtime_names(runtime_jars))
    resolved = []
    for role, items in (("application", apps), ("library", libraries)):
        for item in items:
            resolved.extend(normalizer.add(item, role))
    out_apps = [p for role, p in resolved if role == "application"]
    out_libs = [p for role, p in resolved if role == "library"]
    return out_apps, out_libs, normalizer.report

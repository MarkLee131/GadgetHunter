"""Resolve a target Java runtime into classpath entries, for any JDK version.

The backend (Tai-e) loads the standard library from `java-benchmarks/JREs/jre1.{N}/*.jar`
where N is the configured javaVersion. Java 8 and earlier ship that library as rt.jar; Java 9+
ship it as a module image (lib/modules) with no jar. This module normalizes both into a set of
runtime jars plus the detected feature version, so preparation no longer hard-codes Java 8.

For a modular JDK the modules are extracted once with `jimage` and packed into a single jar,
cached under the user's cache directory keyed by the JDK's identity, so repeated scans reuse it.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
import zipfile
from pathlib import Path

# Class-file major version 52 == Java 8. feature_version = major - 44 for major >= 49 (Java 5).
MAJOR_BASE = 44


def _feature_from_release(java_home):
    """Read the JDK feature version from its `release` file (JAVA_VERSION=...)."""
    release = java_home / "release"
    if release.is_file():
        for line in release.read_text(errors="replace").splitlines():
            if line.startswith("JAVA_VERSION="):
                value = line.split("=", 1)[1].strip().strip('"')
                head = value.lstrip("1.").split(".")[0] if value.startswith("1.") else value.split(".")[0]
                try:
                    return int(head)
                except ValueError:
                    return None
    return None


def _rt_version(rt_jar):
    """Java 8 rt.jar carries its version in the manifest."""
    try:
        with zipfile.ZipFile(rt_jar) as archive:
            for line in archive.read("META-INF/MANIFEST.MF").decode("utf-8", "replace").splitlines():
                if line.startswith("Implementation-Version:"):
                    return line.split(":", 1)[1].strip()
    except (OSError, KeyError, zipfile.BadZipFile):
        pass
    return None


def _jdk_identity(java_home):
    release = java_home / "release"
    stamp = release.read_bytes() if release.is_file() else str(java_home).encode()
    return hashlib.sha256(stamp).hexdigest()[:16]


def _extract_modules(java_home, feature, cache_dir):
    """Extract a modular JDK's standard library into one cached runtime jar."""
    modules = java_home / "lib" / "modules"
    jimage = java_home / "bin" / "jimage"
    if not modules.is_file() or not jimage.is_file():
        raise ValueError(f"Modular JDK without lib/modules or bin/jimage: {java_home}")
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    runtime_jar = cache_dir / f"jdk{feature}-{_jdk_identity(java_home)}-rt.jar"
    if runtime_jar.is_file():
        return runtime_jar
    work = cache_dir / f".extract-{_jdk_identity(java_home)}"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    try:
        subprocess.run([str(jimage), "extract", "--dir", str(work), str(modules)],
                       check=True, capture_output=True, timeout=600)
        # Pack every module's classes into one jar; first definition wins on the rare duplicate.
        tmp = runtime_jar.with_suffix(".jar.tmp")
        written = set()
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_STORED) as out:
            for class_file in sorted(work.rglob("*.class")):
                arc = class_file.relative_to(work)
                # Drop the leading module directory: java.base/java/io/X.class -> java/io/X.class
                arc = Path(*arc.parts[1:]) if len(arc.parts) > 1 else arc
                name = arc.as_posix()
                if name in written or name == "module-info.class" or name.endswith("/module-info.class"):
                    continue
                written.add(name)
                out.write(class_file, name)
        tmp.replace(runtime_jar)
        return runtime_jar
    finally:
        shutil.rmtree(work, ignore_errors=True)


def resolve_runtime(java_home, cache_dir):
    """Return (runtime_jars, feature_version, max_major, version_string) for any JDK.

    runtime_jars: classpath entries holding the target standard library.
    feature_version: 8, 11, 17, ... used as Tai-e's javaVersion.
    max_major: the highest class-file major version to analyze (target's own version).
    """
    java_home = Path(java_home)
    # Java 8 and earlier: rt.jar plus its siblings (jsse, jce, charsets, ...).
    for lib in (java_home / "jre" / "lib", java_home / "lib"):
        rt = lib / "rt.jar"
        if rt.is_file():
            jars = sorted(lib.glob("*.jar"))
            feature = _feature_from_release(java_home) or 8
            return jars, feature, MAJOR_BASE + feature, _rt_version(rt) or f"1.{feature}.0"
    # Java 9+: extract the module image.
    feature = _feature_from_release(java_home)
    if feature is None:
        raise ValueError(f"Cannot determine Java version for {java_home}; no rt.jar and no release file")
    runtime_jar = _extract_modules(java_home, feature, cache_dir)
    return [runtime_jar], feature, MAJOR_BASE + feature, str(feature)

"""Authoritative Java subtype oracle backed by JVM reflection.

Given the target runtime (`java` executable) and classpath, it reports the
transitive supertype set (superclasses + interfaces, including JDK types) of
each queried class, by loading the classes in their native runtime. This seeds
a sound, closed-world subtype relation for the Stage-3 feasibility solver
(cf. Sherman/Garvin/Dwyer, "Deciding Type-Based Partial-Order Constraints").

The oracle degrades gracefully: with no `java`/classpath configured, or for a
class that does not resolve, it reports the type as unknown and the caller
keeps the dependent constraint UNKNOWN rather than guessing.
"""

import logging
import os
import subprocess
import tempfile
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

_HELPER_DIR = os.path.join(os.path.dirname(__file__), "subtype_oracle")
_HELPER_SRC = os.path.join(_HELPER_DIR, "SubtypeOracle.java")


class SubtypeOracle:
    """Resolves class supertype sets via the target JVM. Results are cached."""

    def __init__(self, java_exe: str, classpath: str, javac_exe: Optional[str] = None,
                 timeout: int = 60):
        self.java_exe = java_exe
        self.classpath = classpath or ""
        # Default to the javac beside the java executable, if any.
        self.javac_exe = javac_exe or (
            os.path.join(os.path.dirname(java_exe), "javac") if java_exe else None
        )
        self.timeout = timeout
        self._cache: Dict[str, Optional[Set[str]]] = {}
        self._iface: Set[str] = set()  # class names known to be interfaces
        self._helper_cp: Optional[str] = None
        self._compile_failed = False

    @property
    def available(self) -> bool:
        return bool(self.java_exe and os.path.exists(self.java_exe))

    def _ensure_helper(self) -> Optional[str]:
        """Compile SubtypeOracle.java once with the TARGET's own javac (no
        version flag, so the bytecode matches the target runtime and is always
        runnable on it) into a temp dir; return that dir or None on failure."""
        if self._helper_cp or self._compile_failed:
            return self._helper_cp
        javac = self.javac_exe
        if not javac or not os.path.exists(javac):
            self._compile_failed = True
            logger.warning("Subtype oracle: no javac at %s; casts stay UNKNOWN", javac)
            return None
        out_dir = tempfile.mkdtemp(prefix="gh_subtype_")
        try:
            subprocess.run([javac, "-d", out_dir, _HELPER_SRC],
                           check=True, capture_output=True, timeout=self.timeout)
            self._helper_cp = out_dir
        except Exception as exc:  # compile is best-effort
            self._compile_failed = True
            logger.warning("Subtype oracle: helper compile failed (%s); casts stay UNKNOWN", exc)
        return self._helper_cp

    def supertypes(self, class_names: List[str]) -> Dict[str, Optional[Set[str]]]:
        """Return {class: supertype-set or None-if-unresolved} for each name.

        A class whose value is None did not resolve on the target classpath and
        must be treated as undecided by the caller.
        """
        result: Dict[str, Optional[Set[str]]] = {}
        pending = []
        for name in class_names:
            if name in self._cache:
                result[name] = self._cache[name]
            else:
                pending.append(name)
        if not pending:
            return result
        if not self.available:
            for name in pending:
                self._cache[name] = None
                result[name] = None
            return result
        helper_cp = self._ensure_helper()
        if not helper_cp:
            for name in pending:
                self._cache[name] = None
                result[name] = None
            return result

        sep = ";" if os.name == "nt" else ":"
        run_cp = sep.join(filter(None, [helper_cp, self.classpath]))
        edges: Dict[str, Set[str]] = {}
        errored: Set[str] = set()
        try:
            proc = subprocess.run(
                [self.java_exe, "-cp", run_cp, "SubtypeOracle", *pending],
                capture_output=True, text=True, timeout=self.timeout,
            )
            for line in proc.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 2 and parts[1] == "!ERROR":
                    errored.add(parts[0])
                elif len(parts) == 2 and parts[1] == "!INTERFACE":
                    self._iface.add(parts[0])
                elif len(parts) == 2:
                    edges.setdefault(parts[0], set()).add(parts[1])
        except Exception as exc:
            logger.warning("Subtype oracle: query failed (%s); casts stay UNKNOWN", exc)
            for name in pending:
                self._cache[name] = None
                result[name] = None
            return result

        for name in pending:
            if name in edges and name not in errored:
                value: Optional[Set[str]] = edges[name]
            else:
                value = None  # unresolved → undecided
            self._cache[name] = value
            result[name] = value
        return result

    def is_subtype(self, sub: str, sup: str) -> Optional[bool]:
        """True if `sub` <: `sup`, False if resolved-but-not, None if undecided."""
        sups = self.supertypes([sub]).get(sub)
        if sups is None:
            return None
        return sup in sups

    def cast_feasible(self, a: str, b: str) -> Optional[bool]:
        """Whether a value could satisfy a cast between `a` and `b`: feasible if
        either is a subtype of the other. None if either class is unresolved."""
        res = self.supertypes([a, b])
        sa, sb = res.get(a), res.get(b)
        if sa is None or sb is None:
            return None
        return (b in sa) or (a in sb)

    def is_interface(self, cls: str) -> Optional[bool]:
        """True/False if resolved, None if the class does not resolve."""
        if self.supertypes([cls]).get(cls) is None:
            return None
        return cls in self._iface

    def dispatch_feasible(self, receiver_type: str, callee_class: str) -> Optional[bool]:
        """Can a receiver declared as `receiver_type` dispatch a method defined
        in `callee_class`? Feasible if the two are in a subtype relation. By
        Java single inheritance, two *unrelated concrete classes* share no
        instance, so that is infeasible. If an interface is involved a common
        implementor may exist, so the result is undecided (None) rather than
        a potentially-false negative."""
        res = self.supertypes([receiver_type, callee_class])
        sr, sd = res.get(receiver_type), res.get(callee_class)
        if sr is None or sd is None:
            return None
        if callee_class in sr or receiver_type in sd:
            return True
        if receiver_type not in self._iface and callee_class not in self._iface:
            return False
        return None

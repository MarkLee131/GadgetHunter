"""Tests for sound cast_compatible resolution via the JVM subtype oracle.

The oracle itself needs a JVM and is skipped when none is found; the agent-side
resolution logic (drop feasible / prune impossible / leave undecided) is tested
with a stub oracle so it runs deterministically without Java.
"""
import os
import shutil
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "multi-agents"))

from agents.path_constraint_agent import PathConstraintAgent  # noqa: E402
from tools.analysis.subtype_oracle import SubtypeOracle  # noqa: E402


def _find_java():
    jh = os.environ.get("JAVA_HOME") or os.environ.get("GADGETHUNTER_JAVA_HOME")
    if jh and os.path.exists(os.path.join(jh, "bin", "java")):
        return os.path.join(jh, "bin", "java")
    return shutil.which("java")


class SubtypeOracleJVMTests(unittest.TestCase):
    def setUp(self):
        java = _find_java()
        if not java:
            self.skipTest("no JVM available")
        self.oracle = SubtypeOracle(java, classpath="")
        if not self.oracle.supertypes(["java.util.ArrayList"]).get("java.util.ArrayList"):
            self.skipTest("oracle could not resolve JDK classes (no javac?)")

    def test_cast_decisions(self):
        # subtype → feasible; unrelated → infeasible; unresolved → undecided
        self.assertIs(self.oracle.cast_feasible("java.util.ArrayList", "java.util.List"), True)
        self.assertIs(self.oracle.cast_feasible("java.util.List", "java.util.ArrayList"), True)
        self.assertIs(self.oracle.cast_feasible("java.lang.String", "java.util.List"), False)
        self.assertIsNone(self.oracle.cast_feasible("does.not.Exist", "java.util.List"))


class _StubOracle:
    available = True

    def __init__(self, table):
        self.table = table  # {(a,b): True/False/None}

    def cast_feasible(self, a, b):
        return self.table.get((a, b), self.table.get((b, a)))


class ResolveCastsTests(unittest.TestCase):
    def _agent(self, table):
        agent = PathConstraintAgent(Mock())
        agent._oracle = _StubOracle(table)
        agent._oracle_built = True
        return agent

    def test_feasible_cast_dropped(self):
        agent = self._agent({("com.A", "com.B"): True})
        jd = {"vars": [], "flow": [], "guard": ["type(g0_arg0, com.A)"],
              "runtime": ["cast_compatible(g0_arg0, com.B)"]}
        agent._resolve_casts(jd)
        self.assertEqual(jd["runtime"], [])          # feasible → dropped
        self.assertNotIn("always_throw", jd["guard"])

    def test_impossible_cast_prunes(self):
        agent = self._agent({("com.A", "com.B"): False})
        jd = {"vars": [], "flow": [], "guard": ["type(g0_arg0, com.A)"],
              "runtime": ["cast_compatible(g0_arg0, com.B)"]}
        agent._resolve_casts(jd)
        self.assertEqual(jd["runtime"], [])          # resolved → removed
        self.assertIn("always_throw", jd["guard"])   # impossible → pruned

    def test_unresolved_cast_left_for_unknown(self):
        agent = self._agent({("com.A", "com.B"): None})
        jd = {"vars": [], "flow": [], "guard": ["type(g0_arg0, com.A)"],
              "runtime": ["cast_compatible(g0_arg0, com.B)"]}
        agent._resolve_casts(jd)
        self.assertEqual(jd["runtime"], ["cast_compatible(g0_arg0, com.B)"])  # kept → UNKNOWN

    def test_no_oracle_leaves_casts_untouched(self):
        agent = PathConstraintAgent(Mock())  # no config → no oracle
        jd = {"vars": [], "flow": [], "guard": [],
              "runtime": ["cast_compatible(com.A, com.B)"]}
        agent._resolve_casts(jd)
        self.assertEqual(jd["runtime"], ["cast_compatible(com.A, com.B)"])


if __name__ == "__main__":
    unittest.main()

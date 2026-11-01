"""Tests for inter-gadget type threading (cross-edge dispatch feasibility)."""
import os
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "multi-agents"))

from agents.path_constraint_agent import PathConstraintAgent  # noqa: E402
from tools.java_extraction.call_site import recover_receiver  # noqa: E402


class ReceiverRecoveryTests(unittest.TestCase):
    def test_this_field_receiver(self):
        src = "void run() { this.store.pageOut(o); }"
        self.assertEqual(recover_receiver(src, "pageOut"), "field.store")

    def test_implicit_this_receiver(self):
        src = "void readObject(ObjectInputStream in) { register(); }"
        self.assertEqual(recover_receiver(src, "register"), "this")

    def test_bare_field_receiver(self):
        src = "void run() { store.pageOut(o); }"
        self.assertEqual(recover_receiver(src, "pageOut"), "field.store")

    def test_absent_call(self):
        src = "void run() { somethingElse(); }"
        self.assertIsNone(recover_receiver(src, "pageOut"))


class _StubOracle:
    available = True

    def __init__(self, table):
        self.table = table  # {(R, D): True/False/None}

    def dispatch_feasible(self, r, d):
        return self.table.get((r, d))


class DispatchThreadingTests(unittest.TestCase):
    def _agent(self, table):
        agent = PathConstraintAgent(Mock())
        agent._oracle = _StubOracle(table)
        agent._oracle_built = True
        return agent

    def _ra(self, caller_src):
        caller = {"source_code": caller_src, "method_signature": "<com.Caller: void run()>",
                  "class_name": "com.Caller"}
        callee = {"source_code": "", "method_signature": "<com.X: void pageOut(java.lang.Object)>",
                  "class_name": "com.X"}
        return {"regions": [{"gadgets": [caller, callee]}], "original_chain": []}

    def test_impossible_dispatch_prunes(self):
        agent = self._agent({("com.A", "com.X"): False})
        jd = {"vars": [], "flow": [], "guard": ["type(g0_field.store, com.A)"], "runtime": []}
        agent._thread_gadget_dispatch(self._ra("void run() { this.store.pageOut(o); }"), jd)
        self.assertIn("always_throw", jd["guard"])

    def test_feasible_dispatch_no_prune(self):
        agent = self._agent({("com.A", "com.X"): True})
        jd = {"vars": [], "flow": [], "guard": ["type(g0_field.store, com.A)"], "runtime": []}
        agent._thread_gadget_dispatch(self._ra("void run() { this.store.pageOut(o); }"), jd)
        self.assertNotIn("always_throw", jd["guard"])

    def test_undetermined_dispatch_no_prune(self):
        agent = self._agent({("com.A", "com.X"): None})
        jd = {"vars": [], "flow": [], "guard": ["type(g0_field.store, com.A)"], "runtime": []}
        agent._thread_gadget_dispatch(self._ra("void run() { this.store.pageOut(o); }"), jd)
        self.assertNotIn("always_throw", jd["guard"])

    def test_no_receiver_type_no_prune(self):
        agent = self._agent({("com.A", "com.X"): False})
        jd = {"vars": [], "flow": [], "guard": [], "runtime": []}  # no type() on receiver
        agent._thread_gadget_dispatch(self._ra("void run() { this.store.pageOut(o); }"), jd)
        self.assertNotIn("always_throw", jd["guard"])

    def test_no_oracle_no_prune(self):
        agent = PathConstraintAgent(Mock())  # no oracle
        jd = {"vars": [], "flow": [], "guard": ["type(g0_field.store, com.A)"], "runtime": []}
        agent._thread_gadget_dispatch(self._ra("void run() { this.store.pageOut(o); }"), jd)
        self.assertNotIn("always_throw", jd["guard"])


if __name__ == "__main__":
    unittest.main()

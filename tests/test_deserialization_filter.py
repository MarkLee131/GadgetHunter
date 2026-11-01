"""Tests for the deserialization class-filter model and filter-aware feasibility."""
import os
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "multi-agents"))

from tools.analysis.deserialization_filter import (  # noqa: E402
    DeserializationFilter, from_jasperreports, from_jep290,
)
from agents.path_constraint_agent import PathConstraintAgent  # noqa: E402


class FilterModelTests(unittest.TestCase):
    def test_wildcard_segment_vs_subpackage(self):
        # single '*' matches within one package segment; '**' crosses segments
        f = DeserializationFilter(allow_patterns=["com.x.*", "com.y.**"], mode="whitelist")
        self.assertEqual(f.decide("com.x.Foo"), "allow")
        self.assertEqual(f.decide("com.x.sub.Foo"), "deny")   # '*' stops at the dot
        self.assertEqual(f.decide("com.y.sub.deep.Foo"), "allow")  # '**' spans dots

    def test_whitelist_denies_unmatched_and_matches_inner(self):
        f = DeserializationFilter(allow_exact={"java.util.TreeMap"},
                                  allow_patterns=["java.util.Collections*"], mode="whitelist")
        self.assertEqual(f.decide("java.util.TreeMap"), "allow")
        self.assertEqual(f.decide("java.util.Collections$UnmodifiableMap"), "allow")  # '*'→[^.]*
        self.assertEqual(f.decide("java.lang.Runtime"), "deny")

    def test_array_element_decided(self):
        f = DeserializationFilter(allow_exact={"java.lang.String"}, mode="whitelist")
        self.assertEqual(f.decide("[Ljava.lang.String;"), "allow")

    def test_jep290_allow_deny_unknown(self):
        f = from_jep290("!com.evil.**;java.base/java.util.*;java.lang.*")
        self.assertEqual(f.decide("com.evil.Gadget"), "deny")
        self.assertEqual(f.decide("java.util.ArrayList"), "allow")
        self.assertEqual(f.decide("org.other.Thing"), "unknown")  # jep290: no match → undecided

    def test_jasperreports_properties(self):
        props = (
            "net.sf.jasperreports.deserialization.class.whitelist.core=\\\n"
            "\tnet.sf.jasperreports.engine.*,\\\n"
            "\tjava.util.TreeMap\n"
        )
        f = from_jasperreports(props)
        self.assertIsNotNone(f)
        self.assertEqual(f.decide("net.sf.jasperreports.engine.JRPrintText"), "allow")
        self.assertEqual(f.decide("java.util.TreeMap"), "allow")
        self.assertEqual(f.decide("java.lang.Object"), "allow")   # hardcoded base
        self.assertEqual(f.decide("java.lang.Runtime"), "deny")


class FilterAwarePruneTests(unittest.TestCase):
    def _agent(self, flt):
        agent = PathConstraintAgent(Mock())
        agent._deser_filter = flt
        agent._deser_filter_built = True
        return agent

    def _ra(self, owner_class):
        edge = (f"[INTERFACE] <{owner_class}: void readObject(java.io.ObjectInputStream)> "
                f"--(line:1, constraint:[0])--> <java.lang.Runtime: java.lang.Process exec(java.lang.String)>")
        return {"regions": [{"gadgets": [{"method_signature": edge}]}], "original_chain": [edge]}

    def test_denied_deserialized_class_prunes(self):
        flt = DeserializationFilter(allow_exact={"com.ok.Allowed"}, mode="whitelist")
        agent = self._agent(flt)
        jd = {"vars": [], "flow": [], "guard": [], "runtime": []}
        agent._apply_deserialization_filter(self._ra("com.evil.Gadget"), jd)
        self.assertIn("always_throw", jd["guard"])   # denied → NOT_FEASIBLE

    def test_allowed_deserialized_class_not_pruned(self):
        flt = DeserializationFilter(allow_exact={"com.ok.Allowed"}, mode="whitelist")
        agent = self._agent(flt)
        jd = {"vars": [], "flow": [], "guard": [], "runtime": []}
        agent._apply_deserialization_filter(self._ra("com.ok.Allowed"), jd)
        self.assertNotIn("always_throw", jd["guard"])

    def test_no_filter_no_change(self):
        agent = self._agent(None)
        jd = {"vars": [], "flow": [], "guard": [], "runtime": []}
        agent._apply_deserialization_filter(self._ra("com.evil.Gadget"), jd)
        self.assertEqual(jd["guard"], [])


if __name__ == "__main__":
    unittest.main()

"""Recall benchmark catalog and runner guards (no backend)."""
import json
import tempfile
import unittest
from pathlib import Path

from benchmark_recall import CASES, measure
from scan_rules.triage import load_catalog


class RecallCatalogTests(unittest.TestCase):
    def test_cases_reference_catalogued_families_and_effects(self):
        catalog = load_catalog()
        families = {f["id"] for f in catalog["families"]}
        effects = {e["family"] for e in catalog["effects"]}
        cases = json.loads(CASES.read_text())["cases"]
        self.assertEqual(len({c["id"] for c in cases}), len(cases))
        for case in cases:
            with self.subTest(case=case["id"]):
                self.assertIn(case["family"], families)
                self.assertTrue(set(case["effects"]) <= effects)
                self.assertTrue(case["app"].endswith(".jar"))

    def test_missing_artifacts_are_skipped_not_scanned(self):
        case = {"id": "x", "app": "absent/x.jar", "libs": [], "family": "rome", "effects": ["file-write"]}
        with tempfile.TemporaryDirectory() as folder:
            result = measure(case, Path(folder), "/nonexistent", Path(folder) / "out", 5, 512, ["auto"])
        self.assertEqual(result["status"], "skipped")
        self.assertIn("absent/x.jar", result["reason"])


if __name__ == "__main__":
    unittest.main()

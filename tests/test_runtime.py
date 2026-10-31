import os
import tempfile
import unittest
import zipfile
from pathlib import Path

from scan_rules.runtime import resolve_runtime, MAJOR_BASE


class RuntimeResolverTests(unittest.TestCase):
    def test_java8_runtime_from_rt_jar(self):
        home = os.environ.get("GADGETHUNTER_TEST_JAVA8_HOME")
        if not home:
            self.skipTest("set GADGETHUNTER_TEST_JAVA8_HOME to a JDK 8")
        with tempfile.TemporaryDirectory() as cache:
            jars, feature, max_major, version = resolve_runtime(home, cache)
        self.assertEqual(feature, 8)
        self.assertEqual(max_major, MAJOR_BASE + 8)  # 52
        names = {n for jar in jars for n in zipfile.ZipFile(jar).namelist()}
        self.assertIn("java/io/ObjectInputStream.class", names)

    def test_modular_runtime_extracts_when_available(self):
        home = os.environ.get("GADGETHUNTER_TEST_JAVA_MODERN_HOME")
        if not home or not (Path(home) / "lib" / "modules").is_file():
            self.skipTest("set GADGETHUNTER_TEST_JAVA_MODERN_HOME to a modular JDK (9+)")
        with tempfile.TemporaryDirectory() as cache:
            jars, feature, max_major, version = resolve_runtime(home, cache)
            self.assertGreaterEqual(feature, 9)
            self.assertEqual(max_major, MAJOR_BASE + feature)
            names = {n for jar in jars for n in zipfile.ZipFile(jar).namelist()}
            self.assertIn("java/io/ObjectInputStream.class", names)
            self.assertNotIn("module-info.class", names)
            # Second call reuses the cached extraction.
            jars2, *_ = resolve_runtime(home, cache)
            self.assertEqual(jars, jars2)

    def test_missing_runtime_is_rejected(self):
        with tempfile.TemporaryDirectory() as empty, tempfile.TemporaryDirectory() as cache:
            with self.assertRaises(ValueError):
                resolve_runtime(empty, cache)


if __name__ == "__main__":
    unittest.main()

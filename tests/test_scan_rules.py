"""Regression tests for classpath-derived scan configuration (no model calls)."""
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import yaml
from pathlib import Path

from prepare_scan import compile_profiles, prepare, validate_rule
from scan_rules.inventory import Code, JavaClass, Method, descriptor_types, inventory, native_entries, proxy_entries, read_class

ROOT = Path(__file__).resolve().parents[1]


class RuleTests(unittest.TestCase):
    def test_descriptors(self):
        self.assertEqual(descriptor_types("(I[Ljava/lang/Object;)[[Ljava/lang/String;"),
                         ("java.lang.String[][]", ("int", "java.lang.Object[]")))
        for invalid in ("", "(V)V", "()", "()[V", "()Vjunk", "(L;)V"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                descriptor_types(invalid)

    def test_bad_index_never_defaults_to_receiver(self):
        method = Method("Fixture", "f", "void", ("java.lang.Object",), 0x0009)
        for index in ("base", "result", "typo", -1, 1, True):
            with self.subTest(index=index), self.assertRaises(ValueError):
                validate_rule("sinks", {"method": method.signature, "index": [index]}, method)
        validate_rule("sinks", {"method": method.signature, "index": [0]}, method)

    def test_model_suppression_is_not_a_supported_rule(self):
        method = Method("Fixture", "f", "void", (), 1)
        with self.assertRaises(ValueError):
            validate_rule("sanitizers", {"method": method.signature}, method)
        with self.assertRaises(ValueError):
            validate_rule("ignores", {"method": method.signature, "class": "Fixture"}, method)

    def test_unsafe_ignores_and_overridable_transfers_are_refused(self):
        leaf = Method("p.Final", "size", "int", (), 0x0001, Code(bytes([0x03, 0xac]), 1, 0, {}, {}))
        open_size = Method("p.Open", "size", "int", (), 0x0001, Code(bytes([0x03, 0xac]), 1, 0, {}, {}))
        wrap = Method("p.Open", "wrap", "java.lang.Object", ("java.lang.Object",), 0x0001)
        sink = Method("java.lang.Runtime", "exec", "java.lang.Process", ("java.lang.String",), 1)
        classes = {name: JavaClass(name, "java.lang.Object", (), methods, flags, 52, "x.jar!y", "0" * 64)
                   for name, methods, flags in (("p.Final", (leaf,), 0x31), ("p.Open", (open_size, wrap, Method("p.Open", "<init>", "void", (), 1)), 0x21),
                                                ("java.lang.Runtime", (sink,), 0x21))}
        document = dict(sinks=[{"method": sink.signature, "index": [0]}],
                        transfers=[{"method": wrap.signature, "from": 0, "to": "result"}],
                        imitates=[], ignores=[{"method": leaf.signature}, {"method": open_size.signature}], sanitizers=[])
        with patch("prepare_scan.yaml.safe_load", return_value=document), \
                patch("scan_rules.purity.load_class", side_effect=lambda origin, **_: classes["p.Final"]):
            rules, _, missing, _ = compile_profiles(["jdk-propagation"], classes)
        self.assertEqual(rules["ignores"], [{"method": leaf.signature}])
        self.assertEqual(rules["transfers"], [])
        reasons = {item["method"]: item["reason"] for item in missing if "reason" in item}
        self.assertIn("Overridable", reasons[open_size.signature])
        self.assertIn("Overridable", reasons[wrap.signature])

    def test_unresolved_rules_are_reported(self):
        method = Method("java.lang.Runtime", "exec", "java.lang.Process", ("java.lang.String",), 1)
        cls = JavaClass(method.owner, None, (), (method,), 1, 52, "test.jar", "a" * 64)
        rules, resolved, missing, hashes = compile_profiles(["native-core"], {cls.name: cls})
        self.assertEqual(len(rules["sinks"]), 1)
        self.assertEqual(len(resolved), 1)
        self.assertTrue(missing)
        self.assertIn("native-core", hashes)
        self.assertEqual(rules["ignores"], [])
        self.assertEqual(rules["sanitizers"], [])
        with self.assertRaises(ValueError):
            compile_profiles(["native-core"], {})

    def test_transfer_cannot_shadow_a_sink(self):
        method = Method("Fixture", "read", "java.lang.Object", (), 1)
        cls = JavaClass(method.owner, None, (), (method,), 1, 52, "test.jar", "a" * 64)
        document = dict(sinks=[{"method": method.signature, "index": ["base"]}],
                        transfers=[{"method": method.signature, "from": "base", "to": "result"}],
                        imitates=[], ignores=[], sanitizers=[])
        with patch("prepare_scan.yaml.safe_load", return_value=document), self.assertRaisesRegex(ValueError, "suppress boundaries"):
            compile_profiles(["native-core"], {cls.name: cls})


@unittest.skipUnless(shutil.which("javac"), "JDK compiler required for binary inventory tests")
class InventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.classes = cls.root / "classes"
        cls.classes.mkdir()
        subprocess.run(["javac", "--release", "8", "-d", str(cls.classes),
                        str(ROOT / "tests/fixtures/taint/Callbacks.java")], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_callbacks_and_overloads_come_from_bytecode(self):
        classes = inventory([self.classes])
        # The application inventory omits JDK classes; supply the actual interface relation.
        classes["java.io.Externalizable"] = JavaClass("java.io.Externalizable", "java.lang.Object",
            ("java.io.Serializable",), (), 0x0201, 52, "rt.jar", "b" * 64)
        entries = native_entries(classes)
        self.assertEqual(len(entries), 5, entries)
        self.assertIn("<fixtures.Callbacks: void readObjectNoData()>", entries)
        self.assertIn("<fixtures.InheritedSerializable: void readObjectNoData()>", entries)
        self.assertIn("<fixtures.ExternalCallbacks: void readExternal(java.io.ObjectInput)>", entries)
        self.assertFalse(any("WrongHooks" in item or "NotSerializable" in item for item in entries))

    def test_proxy_entries_select_serializable_invocation_handlers(self):
        classes = inventory([self.classes])
        classes["java.lang.reflect.InvocationHandler"] = JavaClass("java.lang.reflect.InvocationHandler",
            "java.lang.Object", (), (), 0x0201, 52, "rt.jar", "c" * 64)
        roots = proxy_entries(classes)
        self.assertIn("<fixtures.SerializableHandler: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>", roots)
        # A handler that is not Serializable cannot be a deserialized proxy dispatch root.
        self.assertFalse(any("PlainHandler" in r for r in roots))

    def test_truncation_and_newer_bytecode_are_rejected(self):
        data = (self.classes / "fixtures/Callbacks.class").read_bytes()
        with self.assertRaises(ValueError):
            read_class(data[:-1], "truncated.class")
        archive = self.root / "newer.jar"
        with zipfile.ZipFile(archive, "w") as out:
            out.writestr("fixtures/Callbacks.class", data[:6] + b"\x00\x3d" + data[8:])
        with self.assertRaisesRegex(ValueError, "Java 8"):
            inventory([archive])

    def test_duplicate_classes_and_nested_jars_are_explicit_errors(self):
        with self.assertRaisesRegex(ValueError, "Duplicate class"):
            inventory([self.classes, self.classes])
        archive = self.root / "nested.jar"
        with zipfile.ZipFile(archive, "w") as out:
            out.writestr("lib/dependency.jar", b"not-a-jar")
        with self.assertRaisesRegex(ValueError, "Nested JAR"):
            inventory([archive])

    @unittest.skipUnless(os.environ.get("GADGETHUNTER_TEST_JAVA8_HOME"), "Set target Java 8 home to exercise Flash loading")
    def test_real_runtime_and_flash_load_generated_configuration(self):
        output = self.root / "prepared"
        manifest = prepare([self.classes], [], os.environ["GADGETHUNTER_TEST_JAVA8_HOME"],
                           output, ["native-core", "reflection-dispatch"])
        self.assertEqual(manifest["unresolved_rules"], [])
        self.assertEqual(manifest["unresolved_hierarchy_types"], [])
        with self.assertRaisesRegex(ValueError, "already exists"):
            prepare([self.classes], [], os.environ["GADGETHUNTER_TEST_JAVA8_HOME"], output, ["native-core"])
        knowledge = yaml.safe_load((output / "knowledge.yml").read_text())
        self.assertEqual(len(knowledge["imitates"]), 2)
        # Keep the probe outside the target classpath (it is compiled for the host JVM).
        probe = self.root / "probe"
        probe.mkdir()
        jar = ROOT / "multi-agents/flash/flash.jar"
        subprocess.run(["javac", "-cp", str(jar), "-d", str(probe),
                        str(ROOT / "tests/fixtures/taint/FlashConfigProbe.java")],
                       check=True, capture_output=True)
        result = subprocess.run(["java", "-Xmx1G", "-Xss16m", "-cp", os.pathsep.join((str(probe), str(jar))),
                                 "FlashConfigProbe", str(output / "config.yml"), str(output / "knowledge.yml"),
                                 *(str(len(knowledge[section])) for section in ("sinks", "transfers", "imitates"))],
                                cwd=output, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout[-4000:] + result.stderr[-4000:])
        self.assertIn("PREPARED_RULES_AND_CALLBACKS_LOADED", result.stdout)


if __name__ == "__main__":
    unittest.main()


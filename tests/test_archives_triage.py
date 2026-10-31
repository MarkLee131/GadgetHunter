"""Archive normalization and candidate triage (no backend, no model calls)."""
import io
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from scan_rules.archives import normalize
from scan_rules.inventory import Code, JavaClass, Method, inventory, invoked_methods
from scan_rules.triage import parse_chain, runtime_version, triage_chains


def minimal_class(name, major=52, parent="java/lang/Object"):
    """A valid, empty class file: enough for inventory and header checks."""
    def utf8(text):
        raw = text.encode()
        return b"\x01" + struct.pack(">H", len(raw)) + raw
    pool = utf8(name) + b"\x07\x00\x01" + utf8(parent) + b"\x07\x00\x03"
    return (b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, major, 5) + pool
            + struct.pack(">HHHHHHH", 0x21, 2, 4, 0, 0, 0, 0))


def jar(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp())
        self.runtime = self.folder / "rt.jar"
        self.runtime.write_bytes(jar({"java/lang/Object.class": minimal_class("java/lang/Object")}))

    def test_spring_boot_layout_splits_app_and_libraries(self):
        library = jar({"lib/Helper.class": minimal_class("lib/Helper"),
                       "META-INF/versions/11/lib/Helper.class": minimal_class("lib/Helper", 55),
                       "module-info.class": minimal_class("module-info", 53)})
        boot = self.folder / "app.jar"
        boot.write_bytes(jar({"org/springframework/boot/loader/JarLauncher.class": minimal_class("org/springframework/boot/loader/JarLauncher"),
                              "BOOT-INF/classes/app/Main.class": minimal_class("app/Main"),
                              "BOOT-INF/lib/helper.jar": library}))
        apps, libraries, report = normalize([boot], [], [self.runtime], self.folder / "classpath")
        classes = inventory([self.runtime, *apps, *libraries])
        self.assertIn("app.Main", classes)
        self.assertIn("lib.Helper", classes)
        self.assertNotIn("org.springframework.boot.loader.JarLauncher", classes)
        self.assertEqual(len(apps), 1)
        self.assertEqual(len(libraries), 1)
        self.assertEqual(report["dropped_multi_release"], 1)
        self.assertEqual(report["dropped_module_info"], 1)
        self.assertEqual(report["archives"][-1]["kind"], "spring-boot")

    def test_newer_bytecode_and_duplicates_are_reported_not_scanned(self):
        first, second = self.folder / "a.jar", self.folder / "b.jar"
        first.write_bytes(jar({"p/Shared.class": minimal_class("p/Shared")}))
        second.write_bytes(jar({"p/Shared.class": minimal_class("p/Shared"),
                                "p/Modern.class": minimal_class("p/Modern", 61),
                                "p/Old.class": minimal_class("p/Old")}))
        apps, libraries, report = normalize([first], [second], [self.runtime], self.folder / "classpath")
        self.assertEqual(apps, [first])  # unchanged inputs are passed through
        classes = inventory([self.runtime, *apps, *libraries])
        self.assertEqual(classes["p.Shared"].origin.split("!")[0], str(first))
        self.assertIn("p.Old", classes)
        self.assertNotIn("p.Modern", classes)
        self.assertEqual(report["dropped_newer_bytecode"], 1)
        self.assertEqual(report["shadowed_duplicates"], 1)

    def test_runtime_classes_win_over_bundled_copies(self):
        bundled = self.folder / "xml-apis.jar"
        bundled.write_bytes(jar({"java/lang/Object.class": minimal_class("java/lang/Object"),
                                 "x/Y.class": minimal_class("x/Y")}))
        apps, libraries, report = normalize([], [bundled], [self.runtime], self.folder / "classpath")
        self.assertEqual(report["shadowed_duplicates"], 1)
        self.assertIn("x.Y", inventory([self.runtime, *libraries]))


def edge(caller, callee, kind="VIRTUAL"):
    return f"[{kind}] {caller} --(line:1, constraint:[0])--> {callee}"


AIH = "sun.reflect.annotation.AnnotationInvocationHandler"


class TriageTests(unittest.TestCase):
    def test_runtime_versions(self):
        self.assertEqual(runtime_version("1.8.0_432"), (8, 432))
        self.assertEqual(runtime_version("8u71"), (8, 71))
        self.assertEqual(runtime_version("17.0.9"), (17, 9))
        self.assertIsNone(runtime_version(None))
        self.assertIsNone(runtime_version("unknown"))

    def test_decoder_skips_operands_and_switch_padding(self):
        # aload_0; tableswitch (padding, default, low=0, high=0, 1 offset); invokevirtual #1; return
        body = bytes([0x2a, 0xaa, 0, 0]) + struct.pack(">iiii", 0, 0, 0, 0) + bytes([0xb6, 0, 1, 0xb1])
        code = Code(body, 1, 0, {1: ("a.B", "c", "()V")}, {})
        self.assertEqual(invoked_methods(code), {("a.B", "c", "()V")})
        # The operand of sipush happens to equal invokevirtual; it must not be decoded as one.
        code = Code(bytes([0x11, 0xb6, 0x00, 0xb1]), 1, 0, {}, {})
        self.assertEqual(invoked_methods(code), set())

    def test_parse_chain_handles_constructors(self):
        chain = [edge("<a.A: void readObject(java.io.ObjectInputStream)>", "<java.io.FileOutputStream: void <init>(java.lang.String)>", "SPECIAL")]
        self.assertEqual([m[1] for m in parse_chain(chain)], ["readObject", "<init>"])

    def aih_classes(self, rebuilt):
        calls = {1: ("java.io.ObjectInputStream", "readFields", "()Ljava/io/ObjectInputStream$GetField;")} if rebuilt else {}
        body = bytes([0xb6, 0, 1, 0xb1]) if rebuilt else bytes([0xb1])
        read = Method(AIH, "readObject", "void", ("java.io.ObjectInputStream",), 0x0002, Code(body, 2, 0, calls, {}))
        invoke = Method(AIH, "invoke", "java.lang.Object", ("java.lang.Object", "java.lang.reflect.Method", "java.lang.Object[]"), 1)
        cls = JavaClass(AIH, "java.lang.Object", ("java.io.Serializable",), (read, invoke), 0x20, 52, "rt.jar!x", "0" * 64)
        return {AIH: cls}

    def test_dead_route_is_ranked_last_with_evidence(self):
        dead = [edge(f"<{AIH}: void readObject(java.io.ObjectInputStream)>", f"<{AIH}: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>", "INTERFACE"),
                edge(f"<{AIH}: java.lang.Object invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])>", "<app.Lazy: java.lang.Object get(java.lang.Object)>"),
                edge("<app.Lazy: java.lang.Object get(java.lang.Object)>", "<java.lang.Runtime: java.lang.Process exec(java.lang.String)>")]
        live = [edge("<app.Entry: void readObject(java.io.ObjectInputStream)>", "<java.lang.Runtime: java.lang.Process exec(java.lang.String)>")]
        from unittest.mock import patch
        with patch("scan_rules.triage.load_class", side_effect=lambda origin, **_: self.classes[AIH]):
            self.classes = self.aih_classes(rebuilt=True)
            report = triage_chains([dead, live], classes=self.classes, runtime="1.8.0_432")
            first, second = report["candidates"]
            self.assertTrue(first["blocked"])
            self.assertEqual(first["mitigations"][0]["id"], "jdk-aih-membervalues-rebuilt")
            self.assertEqual(second["rank"], 0)
            self.assertEqual(second["effect"], "process-execution")
            # An old runtime without the rebuilt map keeps the route open.
            self.classes = self.aih_classes(rebuilt=False)
            report = triage_chains([dead], classes=self.classes, runtime="1.8.0_25")
            self.assertFalse(report["candidates"][0]["blocked"])
        # Without class facts the evidence cannot be checked: never assume blocked.
        report = triage_chains([dead], runtime="1.8.0_432")
        self.assertFalse(report["candidates"][0]["blocked"])
        self.assertEqual(report["candidates"][0]["mitigations"][0]["status"], "unverified")

    def test_known_core_versus_reusable_trigger(self):
        known = [edge("<java.util.PriorityQueue: void readObject(java.io.ObjectInputStream)>", "<org.apache.commons.beanutils.BeanComparator: int compare(java.lang.Object,java.lang.Object)>"),
                 edge("<org.apache.commons.beanutils.BeanComparator: int compare(java.lang.Object,java.lang.Object)>", "<java.lang.reflect.Method: java.lang.Object invoke(java.lang.Object,java.lang.Object[])>")]
        novel = [edge("<java.util.PriorityQueue: void readObject(java.io.ObjectInputStream)>", "<vendor.Sorter: int compare(java.lang.Object,java.lang.Object)>"),
                 edge("<vendor.Sorter: int compare(java.lang.Object,java.lang.Object)>", "<javax.naming.InitialContext: java.lang.Object lookup(java.lang.String)>")]
        report = triage_chains([known, novel], runtime="1.8.0_432")
        known_item, novel_item = report["candidates"]
        self.assertEqual(known_item["families"], ["commons-beanutils"])
        self.assertEqual(novel_item["novelty"], "novel")
        self.assertIn("java.util.PriorityQueue", novel_item["triggers"])
        self.assertEqual(novel_item["mitigations"][0]["status"], "constrained")
        self.assertEqual(novel_item["rank"], 0)
        self.assertEqual(report["summary"]["novel_unblocked"], 1)

    def test_beanutils_property_facade_is_reflective_and_known(self):
        chain = [edge("<java.util.PriorityQueue: void readObject(java.io.ObjectInputStream)>", "<org.apache.commons.beanutils.BeanComparator: int compare(java.lang.Object,java.lang.Object)>"),
                 edge("<org.apache.commons.beanutils.BeanComparator: int compare(java.lang.Object,java.lang.Object)>", "<org.apache.commons.beanutils.PropertyUtils: java.lang.Object getProperty(java.lang.Object,java.lang.String)>")]
        item = triage_chains([chain], runtime="1.8.0_432")["candidates"][0]
        self.assertEqual(item["families"], ["commons-beanutils"])
        self.assertEqual(item["effect"], "reflective-invocation")

    def test_fastjson2_container_tostring_is_known(self):
        for owner in ("JSONObject", "JSONArray"):
            chain = [edge("<javax.management.BadAttributeValueExpException: void readObject(java.io.ObjectInputStream)>", f"<com.alibaba.fastjson2.{owner}: java.lang.String toString()>"),
                     edge(f"<com.alibaba.fastjson2.{owner}: java.lang.String toString()>", "<java.lang.reflect.Method: java.lang.Object invoke(java.lang.Object,java.lang.Object[])>")]
            item = triage_chains([chain], runtime="1.8.0_432")["candidates"][0]
            self.assertEqual(item["families"], ["fastjson-tostring"])

    def test_own_stream_reads_are_not_secondary_deserializers(self):
        chain = [edge("<vendor.Bag: void readObject(java.io.ObjectInputStream)>", "<java.io.ObjectInputStream: java.lang.Object readObject()>")]

        def bag(new_stream):
            calls = {1: ("java.io.ObjectInputStream", "<init>", "(Ljava/io/InputStream;)V")} if new_stream else {}
            body = bytes([0xb7, 0, 1, 0xb1]) if new_stream else bytes([0xb1])
            read = Method("vendor.Bag", "readObject", "void", ("java.io.ObjectInputStream",), 0x0002, Code(body, 2, 0, calls, {}))
            cls = JavaClass("vendor.Bag", "java.lang.Object", ("java.io.Serializable",), (read,), 0x21, 52, "app.jar!x", "0" * 64)
            stream = JavaClass("java.io.ObjectInputStream", "java.lang.Object", (), (), 0x21, 52, "rt.jar!y", "1" * 64)
            return {cls.name: cls, stream.name: stream}

        from unittest.mock import patch
        for new_stream, expected in ((False, "stream-continuation"), (True, "secondary-deserialization")):
            classes = bag(new_stream)
            with patch("scan_rules.triage.load_class", side_effect=lambda origin, **_: classes["vendor.Bag"]):
                report = triage_chains([chain], classes=classes, runtime="1.8.0_432")
            self.assertEqual(report["candidates"][0]["effect"], expected)
        # Unknown bytecode keeps the higher-priority label.
        self.assertEqual(triage_chains([chain])["candidates"][0]["effect"], "secondary-deserialization")

    def test_clusters_group_same_application_route(self):
        a = [edge("<vendor.A: void readObject(java.io.ObjectInputStream)>", "<java.lang.Runtime: java.lang.Process exec(java.lang.String)>")]
        b = [edge("<vendor.A: void readObject(java.io.ObjectInputStream)>", "<java.lang.StringBuilder: java.lang.String toString()>"),
             edge("<java.lang.StringBuilder: java.lang.String toString()>", "<java.lang.Runtime: java.lang.Process exec(java.lang.String)>")]
        report = triage_chains([b, a], runtime="1.8.0_432")
        self.assertEqual(report["summary"]["clusters"], 1)
        self.assertEqual(report["clusters"][0]["representative"], 1)  # shorter chain represents the group


if __name__ == "__main__":
    unittest.main()


class SelectionTests(unittest.TestCase):
    def test_review_selection_keeps_original_ids(self):
        import json
        from scan_rules.triage import write_review
        from scan_rules.workbench import selected_chains
        folder = Path(tempfile.mkdtemp())
        known = [edge("<java.util.PriorityQueue: void readObject(java.io.ObjectInputStream)>", "<org.apache.commons.beanutils.BeanComparator: int compare(java.lang.Object,java.lang.Object)>"),
                 edge("<org.apache.commons.beanutils.BeanComparator: int compare(java.lang.Object,java.lang.Object)>", "<java.lang.Runtime: java.lang.Process exec(java.lang.String)>")]
        novel = [edge("<vendor.A: void readObject(java.io.ObjectInputStream)>", "<java.lang.Runtime: java.lang.Process exec(java.lang.String)>")]
        chains = [known, novel]
        (folder / "chains").write_text("".join("\n".join(c) + "\n\n" for c in chains))
        (folder / "candidate-index.json").write_text(json.dumps([{"chain_id": 0, "phases": ["baseline"]}, {"chain_id": 1, "phases": ["enhanced"]}]))
        write_review(folder, chains, triage_chains(chains, runtime="1.8.0_432"))
        text, provenance = selected_chains(folder, "review")
        self.assertTrue(text.startswith(novel[0]))
        self.assertEqual([(p["chain_id"], p["source_chain_id"], p["phases"]) for p in provenance],
                         [(0, 1, ["enhanced"]), (1, 0, ["baseline"])])
        self.assertEqual(provenance[1]["triage"]["families"], ["commons-beanutils"])
        text, provenance = selected_chains(folder, "all")
        self.assertTrue(text.startswith(known[0]))

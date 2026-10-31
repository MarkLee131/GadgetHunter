"""Target-derived profiles, coverage gaps and model-proposed gap rules (no network)."""
import json
import unittest
from types import SimpleNamespace

from scan_rules.coverage import coverage_gaps, select_profiles, target_calls
from scan_rules.gaps import gap_candidates, request_gap_proposals, validate_gap_proposals
from scan_rules.inventory import Code, JavaClass, Method
from scan_rules.triage import triage_chains

ENGINE = "<vendor.Engine: java.lang.Object run(java.lang.String)>"


def cls(name, methods, parent="java.lang.Object", interfaces=(), flags=0x21):
    return JavaClass(name, parent, interfaces, tuple(methods), flags, 52, f"x.jar!{name}", "0" * 64)


def calling(owner, name, refs):
    body = b"".join(bytes([0xb9 if iface else 0xb6, 0, i + 1]) + (b"\x01\x00" if iface else b"") for i, (_, iface) in enumerate(refs)) + b"\xb1"
    return Method(owner, name, "void", (), 0x0001, Code(body, 1, 0, {i + 1: ref for i, (ref, _) in enumerate(refs)}, {}))


class FakeClient:
    def __init__(self, document):
        self.document, self.requests = document, []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **request):
        self.requests.append(request)
        message = SimpleNamespace(content=json.dumps(self.document))
        return SimpleNamespace(choices=[SimpleNamespace(finish_reason="stop", message=message)], usage=None)


class CoverageTests(unittest.TestCase):
    def setUp(self):
        run = Method("vendor.Engine", "run", "java.lang.Object", ("java.lang.String",), 0x0401)
        implemented = Method("vendor.Codec", "decode", "java.lang.Object", ("byte[]",), 0x0401)
        caller = calling("app.Main", "go", [(("vendor.Engine", "run", "(Ljava/lang/String;)Ljava/lang/Object;"), True),
                                            (("vendor.Codec", "decode", "([B)Ljava/lang/Object;"), True),
                                            (("missing.lib.Client", "call", "()V"), False),
                                            (("java.lang.reflect.Method", "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;"), False)])
        impl = Method("vendor.CodecImpl", "decode", "java.lang.Object", ("byte[]",), 0x0001)
        self.targets = {"app.Main": cls("app.Main", [caller])}
        self.classes = {**self.targets, "vendor.Engine": cls("vendor.Engine", [run], flags=0x0601),
                        "vendor.Codec": cls("vendor.Codec", [implemented], flags=0x0601),
                        "vendor.CodecImpl": cls("vendor.CodecImpl", [impl], interfaces=("vendor.Codec",))}

    def test_gaps_and_profile_selection(self):
        calls, callers = target_calls(self.targets)
        profiles, reasons = select_profiles(calls)
        self.assertIn("reflection-boundaries", profiles)
        self.assertIn("jdk-propagation", profiles)
        gaps = coverage_gaps(calls, callers, self.classes, covered=set())
        self.assertEqual([g["method"] for g in gaps["unimplemented_methods"]], [ENGINE])
        self.assertIn("missing.lib", [p["package"] for p in gaps["missing_packages"]])
        # A method with a built-in rule is not a gap.
        self.assertEqual(coverage_gaps(calls, callers, self.classes, covered={ENGINE})["unimplemented_total"], 0)

    def test_property_access_profile_selected_on_beanutils_facade_calls(self):
        from collections import Counter
        from scan_rules.coverage import select_profiles
        calls = Counter({("org.apache.commons.beanutils.PropertyUtils", "getProperty", "(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;"): 3})
        profiles, reasons = select_profiles(calls)
        self.assertIn("property-access", profiles)
        self.assertIn("property-access", reasons)
        # No facade call: profile not selected.
        self.assertNotIn("property-access", select_profiles(Counter())[0])

    def test_model_proposals_are_validated_and_marked_as_hypotheses(self):
        calls, callers = target_calls(self.targets)
        manifest = {"coverage_gaps": coverage_gaps(calls, callers, self.classes, covered=set())}
        candidates = gap_candidates(manifest, self.classes)
        method_id = candidates[0]["id"]
        effects = {"expression-evaluation", "process-execution"}
        document = {"proposals": [
            {"method_id": method_id, "kind": "sink", "effect": "expression-evaluation", "inputs": [0], "rationale": "Evaluates script text."},
            {"method_id": method_id, "kind": "transfer", "from": 0, "to": "result", "rationale": "Duplicate."},
            {"method_id": "invented", "kind": "none", "rationale": "x"},
            {"method_id": method_id, "kind": "sink", "effect": "rce", "inputs": [0], "rationale": "Bad family."}]}
        client = FakeClient(document)
        proposals, request = request_gap_proposals(candidates, effects, client=client)
        self.assertNotIn("bytecode", client.requests[0]["messages"][1]["content"])
        accepted, rejected = validate_gap_proposals(proposals, candidates, effects)
        self.assertEqual([a["rule"] for a in accepted], [{"method": ENGINE, "index": [0]}])
        self.assertEqual(accepted[0]["status"], "hypothesis")
        self.assertEqual(len(rejected), 3)
        for bad in ({"method_id": method_id, "kind": "sink", "effect": "process-execution", "inputs": ["base", 5], "rationale": "x"},
                    {"method_id": method_id, "kind": "transfer", "from": 0, "to": 0, "rationale": "x"}):
            self.assertEqual(validate_gap_proposals({"proposals": [bad]}, candidates, effects)[0], [])

    def test_triage_labels_chains_that_rely_on_a_hypothesis(self):
        chain = [f"[INTERFACE] <app.Main: void readObject(java.io.ObjectInputStream)> --(line:1, constraint:[0])--> {ENGINE}"]
        report = triage_chains([chain], hypotheses=[{"method": ENGINE, "section": "sinks", "effect": "expression-evaluation"}])
        item = report["candidates"][0]
        self.assertEqual(item["effect"], "expression-evaluation")
        self.assertEqual(item["mitigations"][0]["id"], "llm-hypothesis")
        self.assertTrue(item["constrained"])


if __name__ == "__main__":
    unittest.main()

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import yaml

from enhance_scan import enhance
from prepare_scan import prepare
from scan_rules.adaptive import collect_candidates, deterministic_proposals, request_proposals, validate_proposals
from scan_rules.inventory import inventory
from scan_rules.runner import run_backend
from scan_rules.summaries import inspect_method

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("javac"), "JDK compiler required")
class AdaptiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.folder = Path(cls.temp.name)
        cls.binary = cls.folder / "classes"
        cls.binary.mkdir()
        subprocess.run(["javac", "--release", "8", "-d", str(cls.binary),
                        str(ROOT / "tests/fixtures/taint/Wrappers.java")], check=True, capture_output=True)
        cls.classes = inventory([cls.binary], include_code=True)
        cls.knowledge = yaml.safe_load((ROOT / "rules/native-core.yml").read_text())

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def proof(self, name, knowledge=None):
        owner = self.classes["fixtures.Wrappers"]
        method = next(m for m in owner.methods if m.name == name)
        return inspect_method(method, owner, knowledge or self.knowledge)

    def test_reference_provenance_and_stream_composition(self):
        for name, source in (("identity", 0), ("cast", 0), ("local", 0), ("wide", 1)):
            with self.subTest(name=name):
                proof = self.proof(name)
                self.assertEqual(proof["status"], "verified", proof)
                self.assertEqual([r["from"] for r in proof["rules"]], [source])
                self.assertTrue(proof["body_sha256"])
        self.assertEqual(self.proof("constant")["status"], "no-flow")
        # A wrapper that builds a new ObjectInputStream contains the secondary
        # deserialization boundary; summarizing it as a transfer would hide it.
        for name in ("stream", "bytes"):
            with self.subTest(name=name):
                self.assertEqual(self.proof(name)["status"], "deferred")

    def test_effects_unknown_control_flow_and_mutation_cannot_be_erased(self):
        for name in ("unrelated", "read", "effect", "branch", "mutate", "override", "sync", "caught"):
            with self.subTest(name=name):
                proof = self.proof(name)
                self.assertEqual(proof["status"], "deferred", proof)
                self.assertEqual(proof["rules"], [])

    def test_constructor_contract_and_sink_roles_must_match(self):
        knowledge = copy.deepcopy(self.knowledge)
        constructor = "<java.io.ObjectInputStream: void <init>(java.io.InputStream)>"
        knowledge["sinks"].append({"method": constructor, "index": [0]})
        self.assertEqual(self.proof("stream", knowledge)["status"], "deferred")
        knowledge["sinks"].pop()
        knowledge["transfers"] = [r for r in knowledge["transfers"] if r["method"] != constructor]
        self.assertEqual(self.proof("stream", knowledge)["status"], "deferred")

    def test_proposals_require_real_identity_evidence_and_independent_proof(self):
        candidates, coverage = collect_candidates(self.classes, self.knowledge)
        document = deterministic_proposals(candidates)
        accepted, rejected = validate_proposals(document, candidates)
        self.assertEqual(len(accepted), 4)
        self.assertEqual(rejected, [])
        valid = document["proposals"][0]
        evil = [dict(valid, method_id="invented"), dict(valid, evidence_offsets=[999999]),
                dict(valid, **{"from": True}), dict(valid, to="base"), dict(valid, sanitizer=True)]
        constant = next(c for c in candidates if " constant(" in c["signature"])
        evil.append(dict(valid, method_id=constant["id"], **{"from": 0, "evidence_offsets": [0]}))
        accepted, rejected = validate_proposals({"proposals": evil}, candidates)
        self.assertEqual(accepted, [])
        self.assertEqual(len(rejected), len(evil))
        self.assertEqual(coverage["deferred_by_budget"], 0)
        _, limited = collect_candidates(self.classes, self.knowledge, 1)
        self.assertGreater(limited["deferred_by_budget"], 0)

    def test_model_request_is_bounded_and_truncated_output_is_rejected(self):
        candidates, _ = collect_candidates(self.classes, self.knowledge, 2)
        client = Mock()
        choice = SimpleNamespace(finish_reason="stop", message=SimpleNamespace(content='{"proposals": []}'))
        client.chat.completions.create.return_value = SimpleNamespace(choices=[choice], usage=None)
        document, request = request_proposals(candidates, client=client)
        self.assertEqual(document, {"proposals": []})
        self.assertEqual(request["requests"], 1)
        self.assertNotIn("tools", client.chat.completions.create.call_args.kwargs)
        choice.finish_reason = "length"
        with self.assertRaisesRegex(ValueError, "finish normally"):
            request_proposals(candidates, client=client)
        client.reset_mock()
        oversized = copy.deepcopy(candidates)
        oversized[0]["bytecode_hex"] = "00" * 100000
        with self.assertRaisesRegex(ValueError, "No request was sent"):
            request_proposals(oversized, client=client)
        client.chat.completions.create.assert_not_called()

    @unittest.skipUnless(os.environ.get("GADGETHUNTER_TEST_JAVA8_HOME"), "Java 8 runtime required")
    def test_enhanced_backend_preserves_effects_and_original_preparation(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            baseline, enhanced = folder / "baseline", folder / "enhanced"
            binary = folder / "classes"
            shutil.copytree(self.binary, binary)
            prepare([binary], [], os.environ["GADGETHUNTER_TEST_JAVA8_HOME"], baseline, ["native-core"])
            config = yaml.safe_load((baseline / "config.yml").read_text())
            config["sources"] = [s for s in config["sources"] if s.startswith("<fixtures.")]
            config["SINK_MAX_TIME"] = 5
            (baseline / "config.yml").write_text(yaml.safe_dump(config))
            before = {name: (baseline / name).read_bytes() for name in ("config.yml", "knowledge.yml", "manifest.json")}
            report = enhance(baseline, enhanced)
            self.assertEqual(len(report["accepted"]), 4)
            for name, content in before.items():
                self.assertEqual((baseline / name).read_bytes(), content)
            for directory in (baseline, enhanced):
                scan = run_backend(directory, timeout=45, heap_mb=1024)
                self.assertEqual(scan["status"], "completed", scan)
                chains = (directory / "chains").read_text()
                # The helper that builds a stream over its parameter is a derived boundary.
                self.assertIn("<fixtures.WrappedRead:", chains)
                self.assertIn("<fixtures.Wrappers: java.io.ObjectInputStream bytes(byte[])>", chains)
                self.assertIn("<fixtures.WrappedEffect:", chains)
                self.assertIn("java.lang.Runtime: java.lang.Process exec(java.lang.String)", chains)
            stale_rules, stale_target = folder / "stale-rules", folder / "stale-target"
            enhance(baseline, stale_rules)
            (stale_rules / "knowledge.yml").write_text("# altered\n" + (stale_rules / "knowledge.yml").read_text())
            with self.assertRaisesRegex(ValueError, "configuration changed"):
                run_backend(stale_rules, timeout=1)
            enhance(baseline, stale_target)
            # Same class names and signatures except one renamed wrapper; proofs
            # must not survive a target rebuild, even before a JVM is launched.
            changed = binary / "fixtures/Wrappers.class"
            changed.write_bytes(changed.read_bytes().replace(b"identity", b"identitx"))
            with self.assertRaisesRegex(ValueError, "bytecode changed"):
                run_backend(stale_target, timeout=1)
            with self.assertRaisesRegex(ValueError, "bytecode changed"):
                enhance(baseline, folder / "stale")

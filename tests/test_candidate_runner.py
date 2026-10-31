import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

import yaml

from prepare_scan import prepare
from scan_rules.runner import ROOT, log_progress, read_candidates, run_backend

EDGE = "[VIRTUAL] <Example: java.lang.Object readResolve()> --(line:8, constraint:[-3, -1])--> <java.lang.Runtime: java.lang.Process exec(java.lang.String)>"


class CandidateRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)

    def fake_prepared(self, *, count=1, exit_code=0, sleep=0, footer=True, loaded=True):
        prepared = self.folder / "prepared"
        prepared.mkdir()
        config = dict(outputDir=str(prepared / "output"), GC_OUT="chains", sources=["callback"],
                      GC_MAX_LEN=25, SINK_MAX_TIME=180, LCS_THRESHOLD=0.8)
        knowledge = dict(sinks=[{}], transfers=[], ignores=[], imitates=[], sanitizers=[])
        manifest = dict(backend_sha256=hashlib.sha256((ROOT / "multi-agents/flash/flash.jar").read_bytes()).hexdigest(),
                        inventory_sha256="fixture", unresolved_rules=[], unresolved_hierarchy_types=[])
        (prepared / "config.yml").write_text(yaml.safe_dump(config))
        (prepared / "knowledge.yml").write_text(yaml.safe_dump(knowledge))
        (prepared / "manifest.json").write_text(json.dumps(manifest))
        output = (EDGE + "\n\n") if count else ""
        if footer:
            output += f"total gadget chains : {count}\n"
        script = self.folder / "fake-java"
        script.write_text(f"#!{sys.executable}\n" +
                          "from pathlib import Path\nimport time,sys\n" +
                          f"out=Path({str(prepared / 'output')!r})\nout.mkdir()\n" +
                          f"(out/'chains').write_text({output!r})\n" +
                          ("print('load 1 sinks, 0 transfers, 0 ignores, 0 imitates, 0 sanitizers',flush=True)\n" if loaded else "") +
                          f"time.sleep({sleep})\nprint('Flash finishes, elapsed time: 0.01s',flush=True)\nsys.exit({exit_code})\n")
        script.chmod(0o700)
        return prepared, str(script)

    def test_completed_search_is_bounded_and_does_not_overwrite_evidence(self):
        folder, java = self.fake_prepared()
        result = run_backend(folder, java=java, timeout=3, heap_mb=256)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["candidate_count"], 1)
        self.assertFalse(result["coverage"]["exhaustive"])
        self.assertEqual((folder / "chains").read_text(), EDGE + "\n\n")
        with self.assertRaisesRegex(ValueError, "already exists"):
            run_backend(folder, java=java)

    def test_zero_candidates_requires_successful_footer_and_rule_loading(self):
        folder, java = self.fake_prepared(count=0)
        result = run_backend(folder, java=java, timeout=3, heap_mb=256)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["candidate_count"], 0)
        self.assertIn("not an exploitability verdict", result["message"])

    def test_timeout_preserves_complete_candidate_blocks_as_partial(self):
        folder, java = self.fake_prepared(sleep=20, footer=False)
        result = run_backend(folder, java=java, timeout=0.15, heap_mb=256)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["candidate_count"], 1)
        self.assertLess(result["elapsed_seconds"], 5)
        self.assertNotEqual(result["exit_code"], 0)

    def test_success_exit_without_loaded_rules_is_partial(self):
        folder, java = self.fake_prepared(loaded=False)
        result = run_backend(folder, java=java, timeout=3, heap_mb=256)
        self.assertEqual(result["status"], "partial")
        self.assertFalse(result["rules_verified_loaded"])

    def test_failure_preserves_candidates_without_success_claim(self):
        folder, java = self.fake_prepared(exit_code=3)
        result = run_backend(folder, java=java, timeout=3, heap_mb=256)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["candidate_count"], 1)

    def test_cancellation_and_launch_failure_leave_terminal_reports(self):
        folder, java = self.fake_prepared(sleep=20)
        cancel = threading.Event()
        cancel.set()
        result = run_backend(folder, java=java, cancel=cancel, timeout=3, heap_mb=256)
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(json.loads((folder / "stage1.json").read_text())["status"], "cancelled")
        other = self.folder / "launch-failure"
        other.mkdir()
        for name in ("manifest.json", "knowledge.yml"):
            shutil.copyfile(folder / name, other / name)
        config = yaml.safe_load((folder / "config.yml").read_text())
        config["outputDir"] = str(other / "output")
        (other / "config.yml").write_text(yaml.safe_dump(config))
        failed = run_backend(other, java=str(self.folder / "missing-java"))
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["candidate_count"], 0)

    def test_truncated_or_mismatched_output_is_not_complete(self):
        path = self.folder / "chains"
        path.write_text(EDGE + "\n")
        self.assertEqual(read_candidates(path)["chains"], [])
        path.write_text(EDGE + "\n\ntotal gadget chains : 0\n")
        self.assertTrue(read_candidates(path)["errors"])
        path.write_text("total gadget chains : 0\n\n" + EDGE + "\n\n")
        self.assertEqual(read_candidates(path)["chains"], [])
        self.assertTrue(read_candidates(path)["errors"])

    def test_exception_type_in_an_edge_is_not_an_error_diagnostic(self):
        path = self.folder / "backend.log"
        path.write_text("[VIRTUAL] <Example: void f(java.lang.Exception)>\njava.lang.NullPointerException: test failure\n")
        self.assertEqual(log_progress(path)["warnings"], ["java.lang.NullPointerException: test failure"])


@unittest.skipUnless(os.environ.get("GADGETHUNTER_TEST_JAVA8_HOME") and shutil.which("javac"), "Java 8 target runtime and host JDK required")
class RealCandidateIntegrationTests(unittest.TestCase):
    def test_actual_search_finds_controlled_effects_but_not_constant_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            classes = folder / "classes"
            classes.mkdir()
            subprocess.run(["javac", "--release", "8", "-d", str(classes),
                            str(ROOT / "tests/fixtures/taint/EffectProbe.java")], check=True, capture_output=True)
            prepared = folder / "prepared"
            prepare([classes], [], os.environ["GADGETHUNTER_TEST_JAVA8_HOME"], prepared, ["native-core"])
            # This tests effect semantics with explicit fixture roots, not whole-runtime coverage.
            config = yaml.safe_load((prepared / "config.yml").read_text())
            config["sources"] = [entry for entry in config["sources"] if entry.startswith("<fixtures.")]
            (prepared / "config.yml").write_text(yaml.safe_dump(config))
            result = run_backend(prepared, timeout=45, heap_mb=1024)
            self.assertEqual(result["status"], "completed", (prepared / "backend.log").read_text()[-4000:])
            chains = (prepared / "chains").read_text()
            self.assertIn("<fixtures.EffectProbe:", chains)
            self.assertIn("<fixtures.NestedProbe:", chains)
            self.assertNotIn("<fixtures.ConstantProbe:", chains)
            self.assertEqual(result["candidate_count"], 2)


if __name__ == "__main__":
    unittest.main()

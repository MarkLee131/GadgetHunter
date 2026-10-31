"""Offline regressions for outcome correctness and durable scan execution."""
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "multi-agents"))

from agents.path_constraint_agent import PathConstraintAgent, Z3SolverStatus
from agents.region_based_coordinator import AnalysisResult, RegionBasedCoordinator
from agents.semantic_reachability_agent import SemanticReachabilityAgent
from templates.z3_translator_template import generate_z3_script_from_json
from tools.analysis.outcomes import InconclusiveAnalysis
from tools.analysis.scan_session import ScanSession, scan_identity
from tools.analysis.chain_parser import validate_chain_file
from tools.core.config import Config, load_config, create_default_config


class OutcomeTests(unittest.TestCase):
    def setUp(self):
        self.solver = PathConstraintAgent(Mock())

    def test_solver_status_determines_verdict_not_boolean(self):
        coordinator = RegionBasedCoordinator.__new__(RegionBasedCoordinator)
        for status, verdict in [("sat", "FEASIBLE"), ("unsat", "NOT_FEASIBLE"),
                                ("unknown", "UNKNOWN"), ("ERROR", "ERROR"), ("garbage", "UNKNOWN")]:
            with self.subTest(status=status):
                self.assertEqual(coordinator._generate_conclusion({}, {
                    "solver_status": status, "is_feasible": True,
                })["verdict"], verdict)

    def test_ambiguous_reachability_does_not_prune(self):
        agent = SemanticReachabilityAgent.__new__(SemanticReachabilityAgent)
        for response in ["", None, "It might be UNREACHABLE", "REACHABLE or UNREACHABLE", "UNREACHABLE extra"]:
            with self.subTest(response=response):
                self.assertIsNone(agent._parse_reachability_response(response)["reachable"])
        self.assertIs(agent._parse_reachability_response("REACHABLE (NO reason given)")["reachable"], True)
        self.assertIs(agent._parse_reachability_response("UNREACHABLE (guard rejects input)")["reachable"], False)

    def test_missing_source_skips_llm(self):
        agent = SemanticReachabilityAgent.__new__(SemanticReachabilityAgent)
        agent.logger = Mock()
        agent.llm_client = Mock()
        result = agent.analyze_region_edge_reachability({}, 0)
        self.assertIsNone(result["reachable"])
        self.assertFalse(result["early_stop"])
        agent.llm_client.ask_with_logging.assert_not_called()

    def test_real_solver_sat_unsat_and_model(self):
        for guards, expected in [(["nonnull(obj)"], "sat"), (["always_throw"], "unsat")]:
            script = generate_z3_script_from_json({"vars": [], "flow": [], "guard": guards, "runtime": []})
            result = self.solver._execute_z3_solver(script)
            self.assertEqual(result["status"], expected, result)
            self.assertGreater(result["constraint_count"], 0)
            if expected == "sat":
                self.assertIsNotNone(result["model"])

    def test_crash_after_sat_is_error(self):
        result = self.solver._execute_z3_solver("print('Result: sat')\nraise RuntimeError('crash')")
        self.assertEqual(result["status"], "error")
        self.assertIn("crash", result["error"])

    def test_invalid_solver_output_is_error(self):
        result = self.solver._execute_z3_solver("print('no result')")
        self.assertEqual(result["status"], "error")

    def test_timeout_is_unknown_without_llm_repair(self):
        self.solver.solver_timeout = 0.05
        result = self.solver._execute_z3_solver("import time\ntime.sleep(10)")
        self.assertEqual(result["status"], "unknown")
        with patch.object(self.solver, "_execute_z3_solver", return_value=result), patch.object(self.solver, "_fix_z3_script_with_llm") as repair:
            self.assertEqual(self.solver._execute_z3_with_fixing("", 0)["status"], "unknown")
            repair.assert_not_called()

    def test_unsupported_constraints_never_become_empty_sat(self):
        for constraints in [
            {"vars": [], "flow": [], "guard": [], "runtime": []},
            {"vars": [], "flow": [], "guard": ["unsupported(x)"], "runtime": []},
            {"vars": [], "flow": [], "guard": ["nonnull(x)"], "runtime": ["cast_compatible(A,B)"]},
            {"vars": [{"name": "x", "constraint": "mystery"}], "flow": [], "guard": [], "runtime": []},
        ]:
            with self.subTest(constraints=constraints), self.assertRaises(InconclusiveAnalysis):
                generate_z3_script_from_json(constraints)

    def test_missing_and_invalid_summary_is_unknown(self):
        for summary in [{"inconclusive": "Missing source"}, {"summary": "garbled"}, {"summary": '{}'}]:
            result = self.solver.verify_path_feasibility({"regions": [{"gadgets": [{"code_summary": summary}]}]}, 0)
            self.assertEqual(result.solver_status, Z3SolverStatus.UNKNOWN)
            self.assertFalse(result.is_feasible)

    def test_final_script_and_error_are_preserved(self):
        result = self.solver._build_feasibility_result(0, {
            "status": "error", "error": "invalid script", "final_script": "repaired", "constraint_count": 2,
        }, "original", 0)
        self.assertEqual(result.error_message, "invalid script")
        self.assertEqual(result.z3_script, "repaired")
        self.assertEqual(result.constraint_count, 2)


class FakeCoordinator:
    def __init__(self, interrupt_at=None, verdict="FEASIBLE"):
        self.calls = []
        self.interrupt_at = interrupt_at
        self.verdict = verdict

    def analyze_chain_with_early_stopping(self, chain, index):
        self.calls.append(index)
        if index == self.interrupt_at:
            raise KeyboardInterrupt()
        return AnalysisResult(index, chain, {"chain_id": index}, {}, {}, {"verdict": self.verdict}, 1.0)


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / "run"
        self.identity = {"sources": "version1", "model": "test"}

    def test_duplicate_chains_execute_once_and_keep_original_ids(self):
        coordinator = FakeCoordinator()
        session = ScanSession(self.output, self.identity)
        results = session.run([["a"], ["a"], ["b"]], coordinator)
        self.assertEqual(coordinator.calls, [0, 2])
        self.assertEqual([r["chain_id"] for r in results], [0, 1, 2])
        self.assertEqual(results[1]["reused_from_chain"], 0)
        self.assertEqual(session.stats["reused"], 1)
        self.assertTrue(session.result_path(1).exists())

    def test_interrupt_checkpoint_and_resume(self):
        chains = [["a"], ["b"], ["c"]]
        session = ScanSession(self.output, self.identity)
        with self.assertRaises(KeyboardInterrupt):
            session.run(chains, FakeCoordinator(interrupt_at=1))
        self.assertTrue(session.result_path(0).exists())
        self.assertEqual(json.loads((self.output / "summary.json").read_text())["completed"], 1)
        resumed = ScanSession(self.output, self.identity, resume=True)
        coordinator = FakeCoordinator()
        results = resumed.run(chains, coordinator)
        self.assertEqual(coordinator.calls, [1, 2])
        self.assertEqual(len(results), 3)
        self.assertEqual(resumed.stats["resumed"], 1)

    def test_resume_rejects_changed_inputs_before_analysis(self):
        ScanSession(self.output, self.identity).run([["a"]], FakeCoordinator())
        coordinator = FakeCoordinator()
        with self.assertRaisesRegex(ValueError, "changed"):
            ScanSession(self.output, {"sources": "version2"}, resume=True).run([["a"]], coordinator)
        self.assertEqual(coordinator.calls, [])

    def test_failed_results_not_deduplicated_and_retried_on_resume(self):
        failed = FakeCoordinator(verdict="UNKNOWN")
        ScanSession(self.output, self.identity).run([["a"], ["a"]], failed)
        self.assertEqual(failed.calls, [0, 1])
        coordinator = FakeCoordinator()
        results = ScanSession(self.output, self.identity, resume=True).run([["a"], ["a"]], coordinator)
        self.assertEqual(coordinator.calls, [0])
        self.assertEqual([r["conclusion"]["verdict"] for r in results], ["FEASIBLE", "FEASIBLE"])

    def test_corrupt_checkpoint_recomputed(self):
        session = ScanSession(self.output, self.identity)
        session.run([["a"]], FakeCoordinator())
        session.result_path(0).write_text('{')
        coordinator = FakeCoordinator()
        ScanSession(self.output, self.identity, resume=True).run([["a"]], coordinator)
        self.assertEqual(coordinator.calls, [0])

    def test_second_writer_refused(self):
        first = ScanSession(self.output, self.identity)
        with first._locked(), self.assertRaisesRegex(ValueError, "already in use"):
            ScanSession(self.output, self.identity).run([["a"]], FakeCoordinator())

    def test_source_and_model_changes_invalidate_identity(self):
        source = self.root / "A.java"
        source.write_text("class A {}")
        config = Config()
        with patch.dict("os.environ", {"GADGETHUNTER_JDK_DIR": ""}):
            before = scan_identity([["a"]], self.root, config)
            source.write_text("class A { int n; }")
            after = scan_identity([["a"]], self.root, config)
            self.assertNotEqual(before, after)
            config.llm_model = "different-model"
            self.assertNotEqual(after, scan_identity([["a"]], self.root, config))


class ConfigAndCLITests(unittest.TestCase):
    def test_config_loading_and_secret_free_template(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict("os.environ", {"OPENAI_API_KEY": "secret-value"}):
            path = Path(temp) / "config.json"
            create_default_config(path)
            self.assertNotIn("secret-value", path.read_text())
            path.write_text(json.dumps({"llm_model": "custom", "max_chains": 7, "solver_timeout": 10}))
            config = load_config(path)
            self.assertEqual((config.llm_model, config.max_chains, config.solver_timeout), ("custom", 7, 10))
            path.write_text('{"solver_timeout": -1}')
            with self.assertRaises(ValueError):
                load_config(path)

    def test_invalid_chain_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "chains"
            path.write_text("<not a real edge>\n")
            self.assertFalse(validate_chain_file(str(path))["valid"])

    def test_cli_preflight_needs_no_api(self):
        from main import main
        with tempfile.TemporaryDirectory() as temp, patch.dict("os.environ", {"OPENAI_API_KEY": "", "GADGETHUNTER_JDK_DIR": ""}):
            root = Path(temp)
            (root / "A.java").write_text("class A {}")
            chains = root / "chains"
            chains.write_text("[VIRTUAL] <A: void f()> --(line:1, constraint:[0])--> <A: void g()>\n")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--check", "--chains-file", str(chains), "--project-root", temp]), 0)
            self.assertFalse((root / "results").exists())



class RequestCacheTests(unittest.TestCase):
    def test_exact_request_cache_and_failed_response_retry(self):
        from collections import OrderedDict
        agent = SemanticReachabilityAgent.__new__(SemanticReachabilityAgent)
        agent.response_cache = OrderedDict()
        agent.cache_size = 2
        agent.cache_hits = 0
        agent.llm_client = SimpleNamespace(provider="test", model="model1", default_params={"temperature": 0.2},
                                           ask_with_logging=Mock(return_value="REACHABLE"))
        valid = lambda r: agent._parse_reachability_response(r)["reachable"] is not None
        first = agent._ask_cached("code1", "system", valid, stage="reachability", chain_id=0)
        second = agent._ask_cached("code1", "system", valid, stage="reachability", chain_id=1)
        self.assertFalse(first[1]["cache_hit"])
        self.assertEqual(second[1], {"cache_hit": True, "cache_source_chain": 0})
        self.assertEqual(agent.llm_client.ask_with_logging.call_count, 1)
        agent._ask_cached("code2", "system", valid, stage="reachability", chain_id=2)
        agent.llm_client.model = "model2"
        agent._ask_cached("code2", "system", valid, stage="reachability", chain_id=3)
        self.assertEqual(agent.llm_client.ask_with_logging.call_count, 3)
        agent.llm_client.ask_with_logging.return_value = "uncertain"
        for _ in range(2):
            agent._ask_cached("code3", "system", valid, stage="reachability")
        self.assertEqual(agent.llm_client.ask_with_logging.call_count, 5)
        self.assertEqual(len(agent.response_cache), 2)

class PipelineIntegrationTests(unittest.TestCase):
    def test_cli_real_parser_solver_checkpoint_and_resume(self):
        from main import main
        class OfflineClient:
            provider = "test"
            model = "offline"
            default_params = {"temperature": 0.2}
            calls = 0
            response = None
            fail = False
            def ask_with_logging(self, prompt, **kwargs):
                self.calls += 1
                if self.fail:
                    raise RuntimeError("API unavailable")
                if self.response is not None:
                    return self.response
                if kwargs.get("stage") == "semantic_reachability":
                    return "REACHABLE"
                return json.dumps({"vars": [], "flow": [], "guard": ["nonnull(obj)"], "runtime": []})
            def get_usage_summary(self):
                return SimpleNamespace(total_prompt_tokens=self.calls, total_completion_tokens=self.calls,
                                       total_tokens=2*self.calls, total_cost_usd=0)
            def print_usage_summary(self):
                pass
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "src" / "demo"
            source.mkdir(parents=True)
            (source / "Example.java").write_text("""package demo;
public class Example {
 public void entry(Object value) { sink(value); }
 public void sink(Object value) { System.out.println(value); }
}
""")
            edge = "[VIRTUAL] <demo.Example: void entry(java.lang.Object)> --(line:3, constraint:[0])--> <demo.Example: void sink(java.lang.Object)>"
            chains = root / "chains"
            chains.write_text(edge + "\n\n" + edge + "\n")
            client = OfflineClient()
            args = ["--batch", "--chains-file", str(chains), "--project-root", str(source.parent), "--output-dir", str(root / "runs")]
            with patch.dict("os.environ", {"OPENAI_API_KEY": "offline-test", "GADGETHUNTER_JDK_DIR": ""}), patch("tools.core.get_llm_client", return_value=client), redirect_stdout(io.StringIO()):
                self.assertEqual(main(args), 0)
                run = next((root / "runs").iterdir())
                summary = json.loads((run / "summary.json").read_text())
                self.assertEqual(summary["analyzed"], 1)
                self.assertEqual(summary["reused"], 1)
                before = client.calls
                self.assertGreater(before, 0)
                self.assertEqual(main(args + ["--resume", str(run)]), 0)
                self.assertEqual(client.calls, before)
                self.assertEqual(json.loads((run / "summary.json").read_text())["resumed"], 2)
                client.response = "ambiguous response"
                self.assertEqual(main(args), 2)
                client.fail = True
                self.assertEqual(main(args), 1)


if __name__ == "__main__":
    unittest.main()

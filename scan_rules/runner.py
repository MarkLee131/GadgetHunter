"""Bounded, observable execution of the bundled candidate-generation backend."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

import yaml

ROOT = Path(__file__).resolve().parents[1]
EDGE = re.compile(r"\[(?:STATIC|SPECIAL|VIRTUAL|INTERFACE|DYNAMIC)\]\s*<.+>\s*--\(line:-?\d+,\s*constraint:\[[^\]]*\]\)-->\s*<.+>")
FOOTER = re.compile(r"total gadget chains\s*:\s*(\d+)")
LOADED = re.compile(r"load (\d+) sinks, (\d+) transfers, (\d+) ignores, (\d+) imitates, (\d+) sanitizers")


def atomic_report(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def read_candidates(path):
    """Only accept complete, well-formed chain blocks and a consistent footer."""
    if not path.exists():
        return {"chains": [], "declared_count": None, "errors": ["Candidate output is missing."]}
    chains, current, errors, declared = [], [], [], None
    # Read by line so a verbose backend does not require a second full text copy.
    with path.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            text = line.strip()
            if not text:
                if current:
                    if all(EDGE.fullmatch(edge) for edge in current):
                        chains.append(current)
                    else:
                        errors.append("Malformed candidate block.")
                    current = []
            elif match := FOOTER.fullmatch(text):
                if declared is not None or current:
                    errors.append("Unexpected candidate footer.")
                declared = int(match.group(1))
            else:
                if declared is not None:
                    errors.append("Data after candidate footer.")
                    break
                current.append(text)
    if current:
        errors.append("Unterminated candidate block; excluded from export.")
    if declared is not None and declared != len(chains):
        errors.append("Candidate footer does not match the parsed chain count.")
    return {"chains": chains, "declared_count": declared, "errors": errors}


def log_progress(path):
    """Observe log counters without loading an unbounded log into memory."""
    values = {"world_classes": None, "world_methods": None, "analyzed_methods": None,
              "loaded_rules": None, "backend_finished": False, "warnings": [],
              "phase": "starting", "call_graph_seconds": None, "current_sink": None}
    if not path.exists():
        return values
    with path.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            if match := re.search(r"(\d+) classes with (\d+) methods in the world", line):
                values["world_classes"], values["world_methods"] = map(int, match.groups())
            if match := re.search(r"have analyzed (\d+) methods", line):
                values["analyzed_methods"] = int(match.group(1))
            if match := LOADED.search(line):
                values["loaded_rules"] = dict(zip(("sinks", "transfers", "ignores", "imitates", "sanitizers"), map(int, match.groups())))
            if "deserialization call graph starts" in line:
                values["phase"] = "call-graph"
            if match := re.search(r"deserialization call graph finishes, elapsed time: ([0-9.]+)s", line):
                values["call_graph_seconds"] = float(match.group(1))
            if "collect gc starts" in line:
                values["phase"] = "candidate-collection"
            if match := re.search(r"backward from (<.+>)", line):
                values["current_sink"] = match.group(1)
            if "Flash finishes, elapsed time:" in line:
                values["backend_finished"] = True
                values["phase"] = "finished"
            if "Cannot find " in line or re.match(r"(?:Exception in thread|Caused by:|(?:[\w$]+\.)*[\w$]*(?:Exception|Error)(?::|\s*$))", line):
                if len(values["warnings"]) < 20:
                    values["warnings"].append(line.strip()[:500])
    return values


def stop_process(process):
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
    except ProcessLookupError:
        process.wait()


def collector_progress(path, expected_sinks):
    """Validate the collector's coverage journal; malformed metadata proves nothing."""
    if not path.exists():
        return None, []
    try:
        data = json.loads(path.read_text())
        if (data.get('schema_version') != 1 or data.get('strategy') != 'round-robin-v1'
                or data.get('status') not in ('running', 'completed', 'partial', 'failed')
                or type(data.get('budget_exhausted')) is not bool or data.get('exhaustive') is not False
                or type(data.get('candidate_count')) is not int or data['candidate_count'] < 0):
            raise ValueError('Invalid collector header')
        sinks = data['sinks']
        if not isinstance(sinks, list) or len(sinks) != len(expected_sinks) or {item['method'] for item in sinks} != expected_sinks:
            raise ValueError('Collector did not account for every configured sink')
        keys = ('incoming_edges', 'controllable_edges', 'scheduled_edges', 'finished_edges',
                'budget_exhausted_edges', 'pending_edges', 'candidates')
        for sink in sinks:
            if any(type(sink.get(key)) is not int or sink[key] < 0 for key in keys):
                raise ValueError('Invalid collector counter')
            if not (sink['incoming_edges'] >= sink['controllable_edges'] >= sink['scheduled_edges'] >=
                    sink['finished_edges'] + sink['budget_exhausted_edges']):
                raise ValueError('Inconsistent collector counters')
            if sink['finished_edges'] + sink['budget_exhausted_edges'] + sink['pending_edges'] != sink['controllable_edges']:
                raise ValueError('Collector lost pending work')
        exhausted = any(s['budget_exhausted_edges'] for s in sinks)
        if data['budget_exhausted'] != exhausted or sum(s['candidates'] for s in sinks) != data['candidate_count']:
            raise ValueError('Inconsistent collector totals')
        if data['status'] in ('completed', 'partial') and any(s['pending_edges'] for s in sinks):
            raise ValueError('Collector finished with unaccounted pending work')
        if (data['status'] == 'completed' and exhausted) or (data['status'] == 'partial' and not exhausted):
            raise ValueError('Collector status contradicts budget accounting')
        return data, []
    except (ValueError, TypeError, KeyError, OSError, AttributeError) as exc:
        return None, [f'Invalid collector coverage journal: {exc}']


def run_backend(prepared, *, timeout=300, heap_mb=4096, stack_mb=16, java="java", cancel=None, backend="stock", collector="stock"):
    """Execute once. A completed process is a bounded search, never a clean verdict.

    A fresh prepared directory is required; existing evidence is never overwritten.
    The cancel event is optional and allows a local job worker to stop the JVM.
    """
    import fcntl

    if timeout <= 0 or heap_mb < 256 or stack_mb < 1:
        raise ValueError("Timeout must be positive, heap at least 256 MiB, and stack at least 1 MiB.")
    folder = Path(prepared).resolve(strict=True)
    with (folder / ".candidate-scan.lock").open("a") as lease:
        try:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError("Candidate generation is already running in this directory.") from exc
        if (folder / "stage1.json").exists() or (folder / "output").exists():
            raise ValueError("Candidate evidence already exists; prepare a fresh output directory.")
        config_path, knowledge_path = folder / "config.yml", folder / "knowledge.yml"
        config = yaml.safe_load(config_path.read_text())
        knowledge = yaml.safe_load(knowledge_path.read_text())
        manifest = json.loads((folder / "manifest.json").read_text())
        if enhancement := manifest.get("enhancement"):
            # Learned summaries are tied to exact bodies and rules. Recheck before
            # launching so a later target rebuild cannot silently reuse old proofs.
            from scan_rules.inventory import inventory
            from scan_rules.summaries import validator_identity
            if enhancement.get("validator_sha256") != validator_identity():
                raise ValueError("Adaptive validator changed; regenerate enhancement before scanning.")
            for path, key in ((config_path, "config_sha256"), (knowledge_path, "knowledge_sha256")):
                if hashlib.sha256(path.read_bytes()).hexdigest() != enhancement.get(key):
                    raise ValueError("Enhanced configuration changed; regenerate enhancement from the baseline.")
            paths = [p.resolve(strict=True) for p in sorted((folder / "java-benchmarks/JREs/jre1.8").glob("*.jar"))]
            paths += [Path(p).resolve(strict=True) for p in config["appClassPath"] + config["classPath"]]
            current = inventory(paths)
            identity = hashlib.sha256(json.dumps(sorted((c.name, c.digest) for c in current.values())).encode()).hexdigest()
            if identity != manifest["inventory_sha256"]:
                raise ValueError("Target bytecode changed; regenerate baseline and enhancement before scanning.")
        jar = ROOT / "multi-agents/flash/flash.jar"
        if hashlib.sha256(jar.read_bytes()).hexdigest() != manifest["backend_sha256"]:
            raise ValueError("Backend changed since preparation; regenerate the configuration.")
        if Path(config["outputDir"]).resolve() != folder / "output" or config["GC_OUT"] != "chains":
            raise ValueError("Prepared output must be the local output/chains path.")
        expected = {section: len(knowledge[section]) for section in ("sinks", "transfers", "ignores", "imitates", "sanitizers")}
        from scan_rules.backend import backend_arguments
        arguments, optimization = backend_arguments(folder, mode=backend, java=java, collector=collector)
        command = [java, f"-Xmx{heap_mb}m", f"-Xss{stack_mb}m", "-XX:+ExitOnOutOfMemoryError",
                   *arguments, "--options-file", str(config_path)]
        report = {
            "schema_version": 1, "status": "running", "stage": "candidate-generation",
            "started_at": time.time(), "command": command, "exit_code": None,
            "limits": {"wall_seconds": timeout, "heap_mb": heap_mb, "stack_mb": stack_mb,
                       "max_chain_length": config["GC_MAX_LEN"], "sink_seconds": config["SINK_MAX_TIME"],
                       "similarity_threshold": config["LCS_THRESHOLD"]},
            "selected_root_count": len(config["sources"]), "candidate_count": 0,
            "config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
            "knowledge_sha256": hashlib.sha256(knowledge_path.read_bytes()).hexdigest(),
            "inventory_sha256": manifest["inventory_sha256"], "backend_sha256": manifest["backend_sha256"],
            "enhancement": manifest.get("enhancement"),
            "backend_optimization": optimization,
            "coverage": {"exhaustive": False, "internal_budget_exhaustion": "not_reported_by_backend",
                         "unresolved_rules": manifest["unresolved_rules"],
                         "unresolved_hierarchy_types": manifest["unresolved_hierarchy_types"]},
            "message": "Building the analysis world and searching from protocol callbacks.",
        }
        report_path, log_path = folder / "stage1.json", folder / "backend.log"
        expected_sinks = {rule['method'] for rule in knowledge['sinks']} if collector == 'fair' else set()

        def observe_collector():
            if collector == 'fair':
                state, errors = collector_progress(folder / 'output/collector.json', expected_sinks)
                report['collector'], report['collector_errors'] = state, errors
                if state:
                    report['candidate_count'] = state['candidate_count']
                    report['coverage']['internal_budget_exhaustion'] = 'collector_reported'
                    report['coverage']['collector_budget_exhausted'] = state['budget_exhausted']

        atomic_report(report_path, report)
        process = None
        started = time.monotonic()
        try:
            with log_path.open("xb") as log:
                process = subprocess.Popen(command, cwd=folder, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                while process.poll() is None:
                    if cancel is not None and cancel.is_set():
                        report.update(status="cancelled", message="Candidate generation cancelled; available evidence is retained.")
                        stop_process(process)
                        break
                    if time.monotonic() - started >= timeout:
                        report.update(status="partial", message="Candidate-generation time limit reached; coverage is incomplete.")
                        stop_process(process)
                        break
                    report["elapsed_seconds"] = round(time.monotonic() - started, 2)
                    report["progress"] = log_progress(log_path)
                    observe_collector()
                    atomic_report(report_path, report)
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        pass
                report["exit_code"] = process.wait()
        except KeyboardInterrupt:
            if process is not None:
                stop_process(process)
                report["exit_code"] = process.returncode
            report.update(status="cancelled", message="Interrupted; available candidate evidence is retained.")
        except OSError as exc:
            report.update(status="failed", message=str(exc))
        finally:
            if process is not None:
                stop_process(process)
            report["elapsed_seconds"] = round(time.monotonic() - started, 2)
            report["finished_at"] = time.time()
            report["progress"] = log_progress(log_path)
            observe_collector()
            parsed = read_candidates(folder / "output/chains")
            report["candidate_count"] = len(parsed["chains"])
            report["output_errors"] = parsed["errors"]
            report["rules_verified_loaded"] = report["progress"]["loaded_rules"] == expected
            if report["status"] == "running":
                if report["exit_code"] != 0 or parsed["errors"] or not report["progress"]["backend_finished"]:
                    report.update(status="failed", message="Backend did not finish with valid candidate output; inspect backend.log.")
                elif parsed["declared_count"] is None or not report["rules_verified_loaded"] or report["progress"]["warnings"]:
                    report.update(status="partial", message="Backend returned with incomplete output or unresolved analysis diagnostics.")
                elif manifest["unresolved_rules"] or manifest["unresolved_hierarchy_types"]:
                    report.update(status="partial", message="Search finished, but unresolved rules or hierarchy types limit coverage.")
                elif collector == 'fair' and (not report.get('collector') or report['collector_errors']
                        or report['collector']['status'] not in ('completed', 'partial')
                        or report['collector']['candidate_count'] != len(parsed['chains'])):
                    report.update(status="partial", message="Collector completion or coverage could not be verified; inspect output/collector.json.")
                elif collector == 'fair' and report['collector']['budget_exhausted']:
                    report.update(status="partial", message="Collector reached per-edge search budgets; unresolved paths remain. Complete candidates are retained.")
                else:
                    report.update(status="completed", message="Bounded candidate search finished. Candidate presence or absence is not an exploitability verdict.")
            # Export only complete validated blocks, even when interrupted or failed.
            export = folder / "chains"
            export.write_text("".join("\n".join(chain) + "\n\n" for chain in parsed["chains"]), encoding="utf-8")
            report["chains_file"] = str(export)
            atomic_report(report_path, report)
        return report

"""Resumable scan orchestration, independent of CLI and HTTP transports."""

import csv
import hashlib
import json
import os
import tempfile
from collections import Counter
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path


CONCLUSIVE = {"FEASIBLE", "NOT_FEASIBLE", "EARLY_STOP"}


def atomic_json(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    name = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as f:
            name = f.name
            json.dump(payload, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if name and os.path.exists(name):
            os.unlink(name)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def tree_digest(root, suffixes):
    """Hash file names and contents once per scan, including dependency sources."""
    root = Path(root).resolve()
    h = hashlib.sha256()
    count = 0
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.suffix in suffixes):
        h.update(str(path.relative_to(root)).encode() + b"\0")
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        h.update(b"\0")
        count += 1
    return {"sha256": h.hexdigest(), "files": count}


def scan_identity(chains, project_root, config):
    root = Path(project_root).resolve()
    if not root.is_dir():
        raise ValueError(f"Source directory does not exist: {root}")
    sources = tree_digest(root, {".java"})
    if not sources["files"]:
        raise ValueError(f"No Java source files found under {root}")
    implementation = Path(__file__).resolve().parents[2]
    jdk_root = os.environ.get("GADGETHUNTER_JDK_DIR")
    if jdk_root:
        jdk_root = Path(jdk_root) / "jdk8u/jdk/src/share/classes"
        if not jdk_root.is_dir():
            raise ValueError(f"JDK source directory does not exist: {jdk_root}")
    return {
        "schema_version": 1, "chains_sha256": digest(chains),
        "project_root": str(root), "sources": sources,
        "jdk_sources": tree_digest(jdk_root, {".java"}) if jdk_root else None,
        "configuration": {key: getattr(config, key) for key in (
            "llm_type", "llm_model", "extract_javadoc", "solver_timeout", "max_fix_attempts",
            "llm_timeout", "llm_max_retries", "llm_cache_size",
        )},
        "implementation": {name: tree_digest(implementation / name, suffixes) for name, suffixes in (
            ("agents", {".py"}), ("tools", {".py"}), ("templates", {".py"}), ("prompts", {".txt"}),
        )},
    }


class ScanSession:
    """One writer per run; each completed chain is durable before the next starts."""

    def __init__(self, output_dir, identity, resume=False):
        self.output_dir = Path(output_dir)
        self.identity = identity
        self.resume = resume
        self.stats = Counter()

    @contextmanager
    def _locked(self):
        import fcntl
        self.output_dir.mkdir(parents=True, exist_ok=True)
        with (self.output_dir / ".scan.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ValueError("This scan directory is already in use") from exc
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def result_path(self, index):
        return self.output_dir / f"chain{index}" / "analysis_results" / f"analysis_result_chain{index}.json"

    def _load_result(self, index, chain):
        try:
            result = json.loads(self.result_path(index).read_text())
            if (isinstance(result, dict)
                    and all(isinstance(result.get(key), dict) for key in (
                        "region_analysis", "semantic_analysis", "feasibility_analysis", "conclusion"))
                    and isinstance(result.get("analysis_time"), (int, float))
                    and result.get("chain_id") == index and result.get("original_chain") == chain
                    and result.get("conclusion", {}).get("verdict") in CONCLUSIVE
                    and result.get("scan_identity") == digest(self.identity)):
                return result
        except (OSError, ValueError, AttributeError):
            pass
        return None

    def run(self, chains, coordinator, max_chains=0, indices=None):
        """Return results in input order; retry ERROR/UNKNOWN checkpoints on resume."""
        if max_chains < 0:
            raise ValueError("max_chains must be nonnegative (0 means all)")
        selected = list(indices) if indices is not None else list(range(len(chains)))[:max_chains or None]
        if any(not 0 <= index < len(chains) for index in selected):
            raise ValueError("Chain index out of range")
        results, reusable = [], {}
        self.stats.clear()
        with self._locked():
            manifest = self.output_dir / "scan.json"
            if self.resume:
                if not manifest.is_file() or json.loads(manifest.read_text()) != self.identity:
                    raise ValueError("Scan inputs, sources, configuration, or implementation changed; start a new scan")
            elif manifest.exists():
                raise ValueError("Scan directory already exists; use --resume or a new directory")
            else:
                atomic_json(manifest, self.identity)
            try:
                for index in selected:
                    chain = chains[index]
                    key = digest(chain)
                    result = self._load_result(index, chain) if self.resume else None
                    if result is not None:
                        self.stats["resumed"] += 1
                    elif key in reusable:
                        original = reusable[key]
                        result = deepcopy(original)
                        result["chain_id"] = index
                        result["region_analysis"]["chain_id"] = index
                        result["analysis_time"] = 0.0
                        result["reused_from_chain"] = original.get("reused_from_chain", original["chain_id"])
                        self.stats["reused"] += 1
                    else:
                        result = asdict(coordinator.analyze_chain_with_early_stopping(chain, index))
                        self.stats["analyzed"] += 1
                    result["scan_identity"] = digest(self.identity)
                    atomic_json(self.result_path(index), result)
                    results.append(result)
                    if result["conclusion"]["verdict"] in CONCLUSIVE:
                        reusable[key] = result
            finally:
                # An interruption leaves every completed chain and a usable partial report.
                self._write_reports(results, len(selected))
        return results

    def _write_reports(self, results, requested):
        with (self.output_dir / "batch_scan_chains_report.csv").open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["chain_id", "verdict", "solver_status", "analysis_time", "reused_from_chain", "result_file"])
            writer.writeheader()
            for r in results:
                writer.writerow({
                    "chain_id": r["chain_id"], "verdict": r["conclusion"]["verdict"],
                    "solver_status": r.get("feasibility_analysis", {}).get("solver_status", ""),
                    "analysis_time": r["analysis_time"], "reused_from_chain": r.get("reused_from_chain", ""),
                    "result_file": str(self.result_path(r["chain_id"]).relative_to(self.output_dir)),
                })
        atomic_json(self.output_dir / "summary.json", {
            "requested": requested, "completed": len(results), **self.stats,
            "verdicts": dict(Counter(r["conclusion"]["verdict"] for r in results)),
        })

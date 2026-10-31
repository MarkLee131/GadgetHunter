"""
Tracks analysis progress and generates reports for batch processing.
"""

import os
import json
import csv
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum

class AnalysisStatus(Enum):
    """Analysis status enum"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ExploitabilityVerdict(Enum):
    """Per-chain verdict (paper §3.5 terminology)."""
    FEASIBLE = "FEASIBLE"               # SAT(Φ(π)) holds — exploitable
    NOT_FEASIBLE = "NOT_FEASIBLE"       # UNSAT(Φ(π)) — solver pruned
    EARLY_STOP = "EARLY_STOP"           # Stage-2 early-stop (unreachable region edge)
    UNKNOWN = "UNKNOWN"                 # insufficient evidence or solver timeout
    ERROR = "ERROR"                     # analysis error

@dataclass
class ChainAnalysisRecord:
    """Analysis record for a single chain"""
    chain_id: int
    chain_file_path: str
    status: AnalysisStatus
    verdict: Optional[ExploitabilityVerdict] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration_seconds: float = 0.0
    error_message: Optional[str] = None
    output_dir: Optional[str] = None
    
    # Resource usage tracking
    token_usage: Dict[str, int] = None
    cost_usd: float = 0.0
    
    # Detailed token tracking by analysis phase (paper §5.4)
    phase_token_usage: Dict[str, Dict[str, int]] = None
    phase_cost_usage: Dict[str, float] = None

    def __post_init__(self):
        if self.token_usage is None:
            self.token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        if self.phase_token_usage is None:
            self.phase_token_usage = {
                "semantic_reachability": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                "code_summary_and_constraints": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                "z3_constraint_solving": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            }
        if self.phase_cost_usage is None:
            self.phase_cost_usage = {
                "semantic_reachability": 0.0,
                "code_summary_and_constraints": 0.0,
                "z3_constraint_solving": 0.0,
            }


@dataclass
class GlobalAnalysisSummary:
    """Aggregate batch statistics (paper §5)."""
    total_chains: int = 0
    completed_chains: int = 0
    failed_chains: int = 0
    skipped_chains: int = 0

    # Verdict statistics — paper §3.5 terminology
    feasible_chains: int = 0             # SAT(Φ(π)) — exploitable
    not_feasible_chains: int = 0         # UNSAT(Φ(π))
    unknown_chains: int = 0
    early_stop_chains: int = 0           # Stage-2 early-stop pruning

    total_duration_hours: float = 0.0
    average_duration_per_chain: float = 0.0
    total_tokens: int = 0
    total_cost_usd: float = 0.0

    success_rate: float = 0.0
    exploitability_rate: float = 0.0     # feasible_chains / completed_chains

    session_start_time: Optional[str] = None
    session_end_time: Optional[str] = None

    def calculate_rates(self):
        if self.total_chains > 0:
            self.success_rate = (self.completed_chains / self.total_chains) * 100

        if self.completed_chains > 0:
            self.exploitability_rate = (self.feasible_chains / self.completed_chains) * 100
            self.average_duration_per_chain = self.total_duration_hours * 3600 / self.completed_chains

    def validate_consistency(self):
        assert self.feasible_chains <= self.completed_chains, "feasible > completed chains"
        assert self.feasible_chains >= 0, "negative feasible chains"


class GlobalAnalysisTracker:
    """Global analysis tracker (simplified version)"""
    
    def __init__(self, output_dir: str = "results", session_name: Optional[str] = None):
        self.output_dir = output_dir
        self.session_name = session_name or f"analysis_{int(time.time())}"
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)

        # Record storage
        self.records: Dict[int, ChainAnalysisRecord] = {}
        self.session_start_time = datetime.now()

        # State file
        self.state_file = os.path.join(self.output_dir, f"{self.session_name}_analysis.json")

        # Try to load existing state (resume support)
        self._load_state()

    def rebuild_from_chain_dirs(self, results_dir: str):
        """Rebuild session from existing chain output directories"""
        import glob
        import re

        print(f"🔍 Scanning directory: {results_dir}")

        # Find all chain directories
        chain_dirs = glob.glob(os.path.join(results_dir, "chain*"))
        chain_dirs.sort(key=lambda x: int(re.findall(r'chain(\d+)', x)[0]) if re.findall(r'chain(\d+)', x) else 0)

        print(f"📁 Found {len(chain_dirs)} chain directories")
        
        for chain_dir in chain_dirs:
            chain_match = re.search(r'chain(\d+)', os.path.basename(chain_dir))
            if not chain_match:
                continue
                
            chain_id = int(chain_match.group(1))
            
            # Look for analysis_result.json (also supports timestamped historical files)
            result_file = os.path.join(chain_dir, "analysis_results", "analysis_result.json")
            # If the standard file is missing, look for timestamped historical files
            if not os.path.exists(result_file):
                # Look for files matching analysis_result_*.json
                import glob
                timestamped_files = glob.glob(os.path.join(chain_dir, "analysis_results", "analysis_result_*.json"))
                if timestamped_files:
                    # Use the newest file (sorted by filename; larger timestamp = newer)
                    result_file = sorted(timestamped_files)[-1]
                    print(f"📁 Chain {chain_id}: using historical file {os.path.basename(result_file)}")
                else:
                    print(f"⚠️ Chain {chain_id}: no analysis_result.json or analysis_result_*.json found")
                    self._create_failed_record(chain_id, chain_dir, "No analysis result file")
                    continue
            
            try:
                # Read analysis result
                with open(result_file, 'r', encoding='utf-8') as f:
                    analysis_data = json.load(f)

                # Extract conclusion
                conclusion = analysis_data.get("conclusion", {})
                verdict_str = conclusion.get("verdict", "UNKNOWN")
                
                # Rebuild record with basic info from on-disk verdict
                record = ChainAnalysisRecord(
                    chain_id=chain_id,
                    chain_file_path=f"chain_{chain_id}",
                    status=AnalysisStatus.COMPLETED,
                    output_dir=chain_dir,
                    start_time="rebuilt",
                    end_time="rebuilt",
                    duration_seconds=0.0,
                )

                try:
                    record.verdict = ExploitabilityVerdict(verdict_str)
                except ValueError:
                    record.verdict = ExploitabilityVerdict.ERROR

                self.records[chain_id] = record

                status_emoji = "✅" if record.verdict == ExploitabilityVerdict.FEASIBLE else "❌"
                print(f"{status_emoji} Chain {chain_id}: {record.verdict.value}")
                
            except Exception as e:
                print(f"❌ Chain {chain_id}: read failed - {e}")
                self._create_failed_record(chain_id, chain_dir, str(e))

        # Save the rebuilt state
        self._save_state()
        print(f"\n✅ Rebuild complete! Processed {len(self.records)} chains")

    def _create_failed_record(self, chain_id: int, chain_dir: str, error: str):
        """Create a failed record"""
        record = ChainAnalysisRecord(
            chain_id=chain_id,
            chain_file_path=f"chain_{chain_id}",
            status=AnalysisStatus.FAILED,
            verdict=ExploitabilityVerdict.ERROR,
            output_dir=chain_dir,
            start_time=datetime.now().isoformat(),
            end_time=datetime.now().isoformat(),
            error_message=error
        )
        self.records[chain_id] = record
    
    def _load_state(self):
        """Load existing analysis state"""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Restore records
                for chain_id_str, record_data in data.get("records", {}).items():
                    chain_id = int(chain_id_str)

                    record = ChainAnalysisRecord(**record_data)
                    # Convert enums
                    record.status = AnalysisStatus(record_data["status"])
                    if record_data.get("verdict"):
                        record.verdict = ExploitabilityVerdict(record_data["verdict"])

                    self.records[chain_id] = record
                
                # Restore session start time
                if data.get("session_start_time"):
                    self.session_start_time = datetime.fromisoformat(data["session_start_time"])

                print(f"📂 Loaded existing analysis state: {len(self.records)} records")

            except Exception as e:
                print(f"⚠️ Failed to load state file: {e}")

    def _save_state(self):
        """Save the full analysis state and summary"""
        try:
            # Get current summary
            summary = self.get_summary()

            # Prepare data to save - includes summary and detailed records
            save_data = {
                "session_info": {
                    "session_name": self.session_name,
                    "session_start_time": self.session_start_time.isoformat(),
                    "last_updated": datetime.now().isoformat()
                },
                "summary": asdict(summary),
                "records": {}
            }
            
            # Convert records to a serializable format
            for chain_id, record in self.records.items():
                record_dict = asdict(record)
                record_dict["status"] = record.status.value
                if record.verdict:
                    record_dict["verdict"] = record.verdict.value
                save_data["records"][str(chain_id)] = record_dict
            
            # Save to file
            with open(self.state_file, 'w', encoding='utf-8') as f:
                json.dump(save_data, f, indent=2, ensure_ascii=False)

        except Exception as e:
            print(f"⚠️ Failed to save state file: {e}")

    def start_chain_analysis(self, chain_id: int, chain_file_path: str, output_dir: str):
        """Start analyzing a chain"""
        record = ChainAnalysisRecord(
            chain_id=chain_id,
            chain_file_path=chain_file_path,
            status=AnalysisStatus.RUNNING,
            start_time=datetime.now().isoformat(),
            output_dir=output_dir
        )
        self.records[chain_id] = record
        self._save_state()
        
        print(f"🚀 Starting analysis of Chain {chain_id}")
    
    def complete_chain_analysis(self, chain_id: int, analysis_result: Dict[str, Any], 
                              token_usage: Optional[Dict[str, int]] = None, cost_usd: float = 0.0,
                              phase_token_usage: Optional[Dict[str, Dict[str, int]]] = None,
                              phase_cost_usage: Optional[Dict[str, float]] = None):
        """Complete analysis of a chain"""
        if chain_id not in self.records:
            print(f"⚠️ Chain {chain_id} record does not exist")
            return

        record = self.records[chain_id]
        record.status = AnalysisStatus.COMPLETED
        record.end_time = datetime.now().isoformat()

        # Compute duration
        if record.start_time:
            start_dt = datetime.fromisoformat(record.start_time)
            end_dt = datetime.fromisoformat(record.end_time)
            record.duration_seconds = (end_dt - start_dt).total_seconds()
        
        # Extract verdict from analysis result
        conclusion = analysis_result.get("conclusion", {})
        verdict_str = conclusion.get("verdict", "ERROR")

        try:
            record.verdict = ExploitabilityVerdict(verdict_str)
        except ValueError:
            record.verdict = ExploitabilityVerdict.ERROR

        if token_usage:
            record.token_usage = token_usage
        record.cost_usd = cost_usd

        if phase_token_usage:
            for phase, usage in phase_token_usage.items():
                if phase in record.phase_token_usage:
                    record.phase_token_usage[phase].update(usage)

        if phase_cost_usage:
            for phase, cost in phase_cost_usage.items():
                if phase in record.phase_cost_usage:
                    record.phase_cost_usage[phase] = cost

        self._save_state()

        verdict_emoji_map = {
            ExploitabilityVerdict.FEASIBLE: "🎯",
            ExploitabilityVerdict.NOT_FEASIBLE: "❌",
            ExploitabilityVerdict.EARLY_STOP: "⚡",
            ExploitabilityVerdict.ERROR: "⚠️",
        }
        emoji = verdict_emoji_map.get(record.verdict, "❓")
        print(f"{emoji} Chain {chain_id} done: {record.verdict.value}")
        
        # Show per-phase token statistics
        if phase_token_usage:
            phase_summary = []
            for phase, usage in record.phase_token_usage.items():
                if usage['total_tokens'] > 0:
                    cost = record.phase_cost_usage.get(phase, 0.0)
                    phase_summary.append(f"{phase}: {usage['total_tokens']} tokens (${cost:.4f})")
            if phase_summary:
                print(f"    📊 Per-phase stats: {', '.join(phase_summary)}")
    
    def get_path_feasibility_analysis_stats(self, chain_id: int) -> dict:
        """
        Get merged statistics for path feasibility analysis

        Path feasibility analysis covers:
        - code_summary_and_constraints: code summarization and constraint extraction
        - z3_constraint_solving: Z3 constraint solving

        Args:
            chain_id: Chain ID

        Returns:
            dict: Merged token usage and cost statistics
        """
        if chain_id not in self.records:
            return {
                "token_usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                "cost_usd": 0.0
            }
        
        record = self.records[chain_id]
        
        # Merge statistics of code_summary_and_constraints and z3_constraint_solving
        feasibility_phases = ["code_summary_and_constraints", "z3_constraint_solving"]
        
        merged_tokens = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        merged_cost = 0.0
        
        for phase in feasibility_phases:
            if phase in record.phase_token_usage:
                phase_tokens = record.phase_token_usage[phase]
                merged_tokens["prompt_tokens"] += phase_tokens.get("prompt_tokens", 0)
                merged_tokens["completion_tokens"] += phase_tokens.get("completion_tokens", 0)
                merged_tokens["total_tokens"] += phase_tokens.get("total_tokens", 0)
            
            if phase in record.phase_cost_usage:
                merged_cost += record.phase_cost_usage[phase]
        
        return {
            "token_usage": merged_tokens,
            "cost_usd": merged_cost
        }
    
    def get_all_path_feasibility_analysis_stats(self) -> dict:
        """
        Get merged path feasibility analysis statistics across all chains

        Returns:
            dict: Aggregated path feasibility analysis statistics over all chains
        """
        total_tokens = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        total_cost = 0.0
        chain_count = 0
        
        for chain_id in self.records:
            feasibility_stats = self.get_path_feasibility_analysis_stats(chain_id)
            
            # Accumulate token usage
            for key in total_tokens:
                total_tokens[key] += feasibility_stats["token_usage"][key]

            # Accumulate cost
            total_cost += feasibility_stats["cost_usd"]

            # Only count chains with actual token usage
            if feasibility_stats["token_usage"]["total_tokens"] > 0:
                chain_count += 1
        
        return {
            "total_token_usage": total_tokens,
            "total_cost_usd": total_cost,
            "analyzed_chains": chain_count,
            "average_tokens_per_chain": total_tokens["total_tokens"] / max(chain_count, 1),
            "average_cost_per_chain": total_cost / max(chain_count, 1)
        }
    
    def fail_chain_analysis(self, chain_id: int, error_message: str):
        """Mark a chain analysis as failed"""
        if chain_id not in self.records:
            # Create failed record
            record = ChainAnalysisRecord(
                chain_id=chain_id,
                chain_file_path="unknown",
                status=AnalysisStatus.FAILED,
                start_time=datetime.now().isoformat()
            )
            self.records[chain_id] = record
        else:
            record = self.records[chain_id]
            record.status = AnalysisStatus.FAILED
        
        record.end_time = datetime.now().isoformat()
        record.error_message = error_message
        record.verdict = ExploitabilityVerdict.ERROR
        
        if record.start_time:
            start_dt = datetime.fromisoformat(record.start_time)
            end_dt = datetime.fromisoformat(record.end_time)
            record.duration_seconds = (end_dt - start_dt).total_seconds()
        
        self._save_state()
        
        print(f"❌ Chain {chain_id} analysis failed: {error_message}")
    

    
    def skip_chain_analysis(self, chain_id: int, reason: str):
        """Skip analysis of a chain"""
        record = ChainAnalysisRecord(
            chain_id=chain_id,
            chain_file_path="unknown",
            status=AnalysisStatus.SKIPPED,
            start_time=datetime.now().isoformat(),
            end_time=datetime.now().isoformat(),
            error_message=reason
        )
        self.records[chain_id] = record
        self._save_state()
        
        print(f"⏭️ Chain {chain_id} skipped: {reason}")
    

    
    def is_chain_completed(self, chain_id: int) -> bool:
        """Check whether a chain's analysis is already finished"""
        record = self.records.get(chain_id)
        return record and record.status in [AnalysisStatus.COMPLETED, AnalysisStatus.FAILED, AnalysisStatus.SKIPPED]
    
    def get_summary(self) -> GlobalAnalysisSummary:
        """Get global summary statistics"""
        summary = GlobalAnalysisSummary()
        summary.session_start_time = self.session_start_time.isoformat()
        summary.session_end_time = datetime.now().isoformat()
        
        for record in self.records.values():
            summary.total_chains += 1

            if record.status == AnalysisStatus.COMPLETED:
                summary.completed_chains += 1
            elif record.status == AnalysisStatus.FAILED:
                summary.failed_chains += 1
            elif record.status == AnalysisStatus.SKIPPED:
                summary.skipped_chains += 1

            if record.verdict == ExploitabilityVerdict.FEASIBLE:
                summary.feasible_chains += 1
            elif record.verdict == ExploitabilityVerdict.NOT_FEASIBLE:
                summary.not_feasible_chains += 1
            elif record.verdict == ExploitabilityVerdict.EARLY_STOP:
                summary.early_stop_chains += 1
            elif record.verdict == ExploitabilityVerdict.UNKNOWN:
                summary.unknown_chains += 1

            # Resource usage only counts real runs (not rebuilt records)
            if record.start_time != "rebuilt":
                summary.total_duration_hours += record.duration_seconds / 3600
                summary.total_tokens += record.token_usage.get("total_tokens", 0)
                summary.total_cost_usd += record.cost_usd

        # Calculate rates
        summary.calculate_rates()
        summary.validate_consistency()

        return summary

    def print_progress(self, current_chain: Optional[int] = None):
        """Print current progress"""
        summary = self.get_summary()

        print(f"\n📊 Analysis progress:")
        print(f"  Total: {summary.total_chains} chains")
        print(f"  Completed: {summary.completed_chains}")
        print(f"  Failed: {summary.failed_chains}")
        print(f"  Skipped: {summary.skipped_chains}")

        if current_chain:
            print(f"  Current: Chain {current_chain}")

        if summary.completed_chains > 0:
            print(f"  🎯 FEASIBLE (SAT(Φ(π))): {summary.feasible_chains}")
            print(f"  ❌ NOT_FEASIBLE: {summary.not_feasible_chains}")
            print(f"  ? UNKNOWN: {summary.unknown_chains}")
            print(f"  ⚡ EARLY_STOP: {summary.early_stop_chains}")
            print(f"  💰 Total cost: ${summary.total_cost_usd:.4f}")

        if summary.total_chains > 0:
            progress_pct = ((summary.completed_chains + summary.failed_chains + summary.skipped_chains) / summary.total_chains) * 100
            print(f"  📈 Progress: {progress_pct:.1f}%")
    
    def get_exploitable_chains(self) -> List[ChainAnalysisRecord]:
        """Return all chains with FEASIBLE verdict (paper §3.5: SAT(Φ(π)))."""
        return [record for record in self.records.values()
                if record.verdict == ExploitabilityVerdict.FEASIBLE]
    
    def get_failed_chains(self) -> List[ChainAnalysisRecord]:
        """Return all chains whose analysis failed"""
        return [record for record in self.records.values() 
                if record.status == AnalysisStatus.FAILED]
    

    
    def generate_reports(self):
        """Generate simplified reports - only a CSV plus one complete JSON"""
        # Only generate the CSV report; the JSON state file already contains everything
        self._generate_csv_report()

        print(f"\n📋 Reports written to: {self.output_dir}")
        print(f"  - Full analysis data: {self.session_name}_analysis.json")
        print(f"  - CSV report: {self.session_name}_chains_report.csv")
    

    
    def _generate_csv_report(self):
        """Generate CSV-format report"""
        csv_file = os.path.join(self.output_dir, f"{self.session_name}_chains_report.csv")
        
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            if not self.records:
                return
            
            # Core fields plus simplified verification fields
            core_fieldnames = [
                "chain_id", "chain_file_path", "status", "verdict", 
                "start_time", "end_time", "duration_seconds", 
                "error_message", "output_dir"
            ]
            
            writer = csv.DictWriter(f, fieldnames=core_fieldnames)
            writer.writeheader()
            
            for record in self.records.values():
                row_data = {
                    "chain_id": record.chain_id,
                    "chain_file_path": record.chain_file_path,
                    "status": record.status.value,
                    "verdict": record.verdict.value if record.verdict else None,
                    "start_time": record.start_time,
                    "end_time": record.end_time,
                    "duration_seconds": record.duration_seconds,
                    "error_message": record.error_message,
                    "output_dir": record.output_dir
                }
                writer.writerow(row_data)
    
    def print_final_summary(self):
        """Print final summary"""
        summary = self.get_summary()
        exploitable_chains = self.get_exploitable_chains()

        print(f"\n🎯 Final analysis results:")
        print(f"=" * 60)
        print(f"Total chains: {summary.total_chains}")
        print(f"Successfully analyzed: {summary.completed_chains} ({summary.success_rate:.1f}%)")
        print(f"")
        print(f"📊 Detailed statistics (paper §3.5 verdict):")
        print(f"  🎯 FEASIBLE (SAT(Φ(π)) — exploitable): {summary.feasible_chains} ({summary.exploitability_rate:.1f}%)")
        print(f"  ❌ NOT_FEASIBLE: {summary.not_feasible_chains}")
        print(f"  ? UNKNOWN: {summary.unknown_chains}")
        print(f"  ⚡ EARLY_STOP: {summary.early_stop_chains}")

        # Only show time and cost for non-rebuilt data
        has_real_analysis = any(record.start_time != "rebuilt" for record in self.records.values())
        if has_real_analysis:
            print(f"")
            print(f"⏱️ Resource usage:")
            print(f"  Total time: {summary.total_duration_hours:.2f} hours")
            print(f"  Total cost: ${summary.total_cost_usd:.4f}")
        else:
            print(f"")
            print(f"(Rebuilt data - no time/cost statistics)")
        print(f"=" * 60)
        
        if exploitable_chains:
            print(f"\n✅ FEASIBLE (exploitable) chains ({len(exploitable_chains)}):")
            for record in exploitable_chains[:10]:
                print(f"  - Chain {record.chain_id}: {record.output_dir}")
            if len(exploitable_chains) > 10:
                print(f"  ... and {len(exploitable_chains) - 10} more")
        else:
            print(f"\nNo FEASIBLE chains found")

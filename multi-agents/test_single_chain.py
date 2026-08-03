#!/usr/bin/env python3
"""
Single-chain smoke test for GadgetHunter (paper §3.2 pipeline).

Runs the three stages on one candidate chain end-to-end:
  Stage 1  Region partitioning         (paper §3.4 Algorithm 1)
  Stage 2  Semantic reachability       (paper §3.4.3, with early-stop)
  Stage 3  Path feasibility (Z3 over   (paper §3.5)
           ⟨Vars, Flow, Guard, Runtime⟩)

Verdicts (paper §3.5):
  FEASIBLE      SAT(Φ(π)) holds — chain is exploitable
  NOT_FEASIBLE  UNSAT(Φ(π))
  NOT_REACHABLE Stage-2 LLM declared an inter-region edge unreachable
  EARLY_STOP    Stage-2 early-stop pruning triggered
  ERROR         analysis error
"""

import os
import sys
import time
import json
import argparse

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from tools.core import Config, get_llm_client
from tools.analysis import parse_chains_file
from agents.region_based_coordinator import RegionBasedCoordinator


def load_and_select_chain(chains_file: str, chain_index: int = 0):
    chains = parse_chains_file(chains_file)
    if not chains:
        print(f"No chains found in {chains_file}")
        return None
    if chain_index >= len(chains):
        print(f"Chain index {chain_index} out of range (0..{len(chains)-1})")
        return None
    print(f"Loaded {len(chains)} chains; selected chain {chain_index} ({len(chains[chain_index])} gadgets)")
    return chains[chain_index]


def print_analysis_results(result, analysis_time: float) -> None:
    print(f"\nAnalysis completed in {analysis_time:.2f}s")
    print("=" * 80)
    print(f"Chain ID: {result.chain_id}")

    metadata = (result.region_analysis or {}).get("analysis_metadata", {})
    print(f"\nRegion Analysis (paper §3.4):")
    print(f"  Total Regions:    {metadata.get('total_regions', 0)}")
    print(f"  Static Regions:   {metadata.get('static_regions', 0)}")
    print(f"  LLM Regions:      {metadata.get('llm_regions', 0)}")
    print(f"  Total Transitions:{metadata.get('total_transitions', 0)}")

    semantic = result.semantic_analysis or {}
    early_stop = semantic.get("early_stop", False)
    print(f"\nSemantic Reachability (paper §3.4.3):")
    print(f"  Early Stop:       {early_stop}")
    if early_stop:
        failed = semantic.get("failed_edge", {})
        reach = semantic.get("reachability_result", {})
        print(f"  Failed Edge:      {failed.get('transition_type', 'Unknown')} (idx {failed.get('edge_index', '?')})")
        print(f"  Reason:           {reach.get('reasoning', 'No reason provided')}")
    else:
        print(f"  All Edges Reachable: {semantic.get('all_edges_reachable', semantic.get('reachability_validated', False))}")

    feas = result.feasibility_analysis or {}
    print(f"\nPath Feasibility (paper §3.5):")
    if early_stop:
        print(f"  Status: SKIPPED (early stop)")
    else:
        print(f"  Solver Status:    {feas.get('solver_status', 'UNKNOWN')}")
        print(f"  SAT(Φ(π)):        {feas.get('is_feasible', False)}")
        print(f"  Constraint Count: {feas.get('constraint_count', 0)}")
        print(f"  Execution Time:   {feas.get('execution_time', 0.0):.2f}s")
        # Surface the four-tuple for audit
        json_constraints = feas.get("json_constraints", {}) or {}
        if json_constraints:
            print(f"  ⟨Vars, Flow, Guard, Runtime⟩ sizes: "
                  f"{len(json_constraints.get('vars', []))} / "
                  f"{len(json_constraints.get('flow', []))} / "
                  f"{len(json_constraints.get('guard', []))} / "
                  f"{len(json_constraints.get('runtime', []))}")

    conclusion = result.conclusion or {}
    print(f"\nFinal Verdict: {conclusion.get('verdict', 'UNKNOWN')}")
    print(f"Reasoning:     {conclusion.get('reasoning', 'No reason')}")
    print("=" * 80)


def save_single_chain_results(result) -> str:
    out_dir = "single_chain_results"
    os.makedirs(out_dir, exist_ok=True)
    ts = os.environ.get("SCRIPT_START_TIME", time.strftime("%Y%m%d_%H%M%S"))
    out_path = os.path.join(out_dir, f"{ts}_chain_{result.chain_id}.json")

    semantic = result.semantic_analysis or {}
    payload = {
        "analysis_result": {
            "chain_id": result.chain_id,
            "original_chain": result.original_chain,
            "region_analysis": result.region_analysis,
            "semantic_analysis": result.semantic_analysis,
            "feasibility_analysis": result.feasibility_analysis,
            "conclusion": result.conclusion,
            "analysis_time": result.analysis_time,
            "error": result.error,
        },
        "test_metadata": {
            "framework": "GadgetHunter (FSE26)",
            "timestamp": int(time.time()),
            "early_stop_triggered": semantic.get("early_stop", False),
            "failed_edge_index": (semantic.get("failed_edge", {}) or {}).get("edge_index") if semantic.get("early_stop") else None,
        },
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    print(f"Results saved to {out_path}")
    return out_path


def main() -> int:
    parser = argparse.ArgumentParser(description="GadgetHunter single-chain smoke test")
    parser.add_argument("--chains-file", required=True, help="Path to a flash chains dump")
    parser.add_argument("--project-root", required=True, help="Java project under analysis")
    parser.add_argument("--chain-index", type=int, default=0, help="Index of chain to analyse (default 0)")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    os.environ.setdefault("SCRIPT_START_TIME", time.strftime("%Y%m%d_%H%M%S"))
    print(f"Session: {os.environ['SCRIPT_START_TIME']}")
    print(f"Chains file:   {args.chains_file}")
    print(f"Project root:  {args.project_root}")
    print(f"Chain index:   {args.chain_index}")

    if not os.path.exists(args.chains_file):
        print(f"Chains file not found: {args.chains_file}")
        return 1
    if not os.path.exists(args.project_root):
        print(f"Project path not found: {args.project_root}")
        return 1

    config = Config()
    config.llm_type = "gpt"
    config.llm_model = "gpt-4.1"  # paper §4
    config.debug = args.debug
    config.configure_logging()

    llm_config = config.get_llm_config()
    if not llm_config.get("api_key"):
        print("OPENAI_API_KEY is not set.")
        return 1

    chain = load_and_select_chain(args.chains_file, args.chain_index)
    if not chain:
        return 1

    llm_client = get_llm_client(llm_config)
    coordinator = RegionBasedCoordinator(
        llm_client=llm_client,
        project_root=args.project_root,
        debug=args.debug,
    )

    start = time.time()
    try:
        result = coordinator.analyze_chain_with_early_stopping(chain, args.chain_index)
    except Exception as e:
        print(f"Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return 1

    print_analysis_results(result, time.time() - start)
    save_single_chain_results(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())

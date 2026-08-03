#!/usr/bin/env python3
"""
GadgetHunter main entry point (paper §4 Implementation).

Runs the three-stage pipeline coordinated by RegionBasedCoordinator:
  Stage 1 (taint) → Stage 2 (region-based semantic reachability)
                  → Stage 3 (SMT path feasibility over ⟨Vars, Flow, Guard, Runtime⟩).
"""

import argparse
import os
import json
import time
import sys
from typing import List
import logging

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from tools.core import Config, USE_EARLY_STOPPING
from tools.core import get_llm_client
from tools.analysis import parse_chains_file
from agents.region_based_coordinator import RegionBasedCoordinator, AnalysisResult
from utils.global_analysis_tracker import GlobalAnalysisTracker


def setup_logging(debug: bool = False, output_dir: str = "results"):
    """Setup logging configuration"""
    level = logging.DEBUG if debug else logging.INFO

def setup_directories(config: Config, project_name: str = None):
    """Setup output directories with timestamp and project organization"""
    import time
    
    # Create timestamped directory with project name
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    if project_name:
        session_dir = f"{timestamp}_{project_name}"
    else:
        session_dir = timestamp
    
    # Update config to use session-specific directory
    config.session_output_dir = os.path.join(config.output_dir, session_dir)
    os.makedirs(config.session_output_dir, exist_ok=True)
    
    print(f"📁 Session output directory: {config.session_output_dir}")
    return config.session_output_dir

def setup_chain_directories(session_output_dir: str, chain_id: int, debug: bool = False) -> str:
    """Setup chain-specific output directories"""
    # Create chain-specific directory
    chain_dir = os.path.join(session_output_dir, f"chain{chain_id}")
    os.makedirs(chain_dir, exist_ok=True)
    
    # Always create basic directories for this chain
    basic_dirs = ["analysis_results"]
    for basic_dir in basic_dirs:
        os.makedirs(os.path.join(chain_dir, basic_dir), exist_ok=True)
    
    if debug:
        debug_dirs = ["llm_logs", "z3_debug"]
        for debug_dir in debug_dirs:
            os.makedirs(os.path.join(chain_dir, debug_dir), exist_ok=True)
    
    print(f"📁 Chain {chain_id} output directory: {chain_dir}")
    return chain_dir


def save_results(results: List[AnalysisResult], session_output_dir: str) -> str:
    """Save analysis results to chain-specific JSON files"""
    saved_files = []
    
    for result in results:
        chain_id = result.chain_id
        chain_dir = os.path.join(session_output_dir, f"chain{chain_id}", "analysis_results")
        os.makedirs(chain_dir, exist_ok=True)
        
        output_file = f"analysis_result_chain{chain_id}.json"
        output_path = os.path.join(chain_dir, output_file)
        
        # Convert single result to serializable format
        serializable_result = {
            "chain_id": result.chain_id,
            "original_chain": result.original_chain,
            "region_analysis": result.region_analysis,
            "semantic_analysis": result.semantic_analysis,
            "feasibility_analysis": result.feasibility_analysis,
            "conclusion": result.conclusion,
            "analysis_time": result.analysis_time,
            "error": result.error,
        }
        
        # Save individual chain result
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(serializable_result, f, ensure_ascii=False, indent=2)
        
        saved_files.append(output_path)
        print(f"Chain {chain_id} result saved to: {output_path}")
    
    print(f"All results saved to {len(saved_files)} chain-specific files")
    return f"{len(saved_files)} files saved"


def print_chain_selection(chains: List[str]):
    """Print available chains for selection"""
    print("\n" + "="*80)
    print("AVAILABLE GADGET CHAINS")
    print("="*80)
    
    for idx, chain in enumerate(chains):
        print(f"[{idx}] {chain}")
    
    print("="*80)


def print_analysis_summary(result: AnalysisResult):
    """Print analysis summary"""
    print("\n" + "="*80)
    print("ANALYSIS SUMMARY")
    print("="*80)
    
    chain_id = result.chain_id
    print(f"Chain ID: {chain_id}")
    
    # Original chain
    original_chain = result.original_chain
    if original_chain:
        print(f"\nOriginal Chain:")
        for i, step in enumerate(original_chain):
            print(f"  {i+1}. {step}")
    
    # Analysis metadata
    region_analysis = result.region_analysis
    metadata = region_analysis.get("analysis_metadata", {})
    print(f"\nAnalysis Metadata:")
    print(f"  Total Regions: {metadata.get('total_regions', 0)}")
    print(f"  Static Regions: {metadata.get('static_regions', 0)}")
    print(f"  LLM Regions: {metadata.get('llm_regions', 0)}")
    print(f"  Total Transitions: {metadata.get('total_transitions', 0)}")
    
    # Early stopping information
    semantic_analysis = result.semantic_analysis
    early_stop = semantic_analysis.get("early_stop", False)
    print(f"\nEarly Stopping Analysis:")
    print(f"  Early Stop Triggered: {early_stop}")
    
    if early_stop:
        failed_edge = semantic_analysis.get("failed_edge", {})
        reachability_result = semantic_analysis.get("reachability_result", {})
        print(f"  Failed Edge: {failed_edge.get('transition_type', 'Unknown')}")
        print(f"  Edge Index: {failed_edge.get('edge_index', 'Unknown')}")
        print(f"  Unreachable Reason: {reachability_result.get('reasoning', 'No reason provided')}")
    
    # Conclusion
    conclusion = result.conclusion
    print(f"\nFinal Verdict: {conclusion.get('verdict', 'UNKNOWN')}")
    print(f"Reasoning: {conclusion.get('reasoning', 'No reasoning provided')}")
    
    # Feasibility analysis
    feasibility = result.feasibility_analysis
    print(f"\nZ3 Analysis:")
    if early_stop:
        print(f"  Status: SKIPPED (Early Stop)")
        print(f"  Reason: {feasibility.get('reason', 'Region edge unreachable')}")
    else:
        print(f"  Solver Status: {feasibility.get('solver_status', 'UNKNOWN')}")
        print(f"  Is Feasible: {feasibility.get('is_feasible', False)}")
        print(f"  Constraint Count: {feasibility.get('constraint_count', 0)}")
        print(f"  Execution Time: {feasibility.get('execution_time', 0.0):.2f}s")
    
    # Analysis time
    print(f"\nAnalysis Time: {result.analysis_time:.2f}s")

    if result.error:
        print(f"\nError: {result.error}")


def select_chain_interactive(chains: List[str]) -> int:
    """Select chain interactively"""
    print_chain_selection(chains)
    
    while True:
        try:
            choice = input(f"\nSelect chain (0-{len(chains)-1}): ").strip()
            chain_idx = int(choice)
            
            if 0 <= chain_idx < len(chains):
                return chain_idx
            else:
                print(f"Invalid choice. Please enter a number between 0 and {len(chains)-1}")
        except ValueError:
            print("Invalid input. Please enter a number.")
        except KeyboardInterrupt:
            print("\nExiting...")
            sys.exit(0)


def load_chains(chains_file: str = None) -> List[List[str]]:
    """Load gadget chains from file or use default test chains"""
    
    # If chains file provided, load from file
    if chains_file and os.path.exists(chains_file):
        print(f"Loading chains from: {chains_file}")
        try:
            chains = parse_chains_file(chains_file)
            if chains:
                print(f"✅ Loaded {len(chains)} chains from file")
                return chains
            else:
                print(f"❌  No chains found in file")
        except Exception as e:
            print(f"❌ Error loading chains from file: {e}")
    
    return []



def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Multi-Agent Framework")
    parser.add_argument("--config", "-c", help="Configuration file path")
    parser.add_argument("--project-root", "-p", help="Project root directory")
    parser.add_argument("--chains-file", "-f", required=True, help="Gadget chains file path")
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug mode")
    parser.add_argument("--batch", "-b", action="store_true", help="Run batch analysis")
    parser.add_argument("--max-chains", "-m", type=int, default=5, help="Maximum chains to analyze")
    parser.add_argument("--interactive", "-i", action="store_true", help="Interactive mode")
    parser.add_argument("--resume", "-r", help="Resume from existing session (provide session name)")
    parser.add_argument("--rebuild", help="Rebuild session from existing chain output directories (provide results directory)")
    
    args = parser.parse_args()
    
    try:
        # Load configuration first
        config = Config()
        config.llm_type = "gpt"
        config.llm_model = "gpt-4.1"
        config.debug = args.debug
        config.configure_logging()
        
        if args.debug:
            config.debug = True
        
        # Extract project name from project_root and set in config
        if args.project_root:
            config.set_project_info(project_path=args.project_root)
        
        # Setup directories with timestamp and project organization
        session_output_dir = setup_directories(config, config.project_name)
        
        # Setup logging with session-specific output directory
        setup_logging(args.debug, session_output_dir)
        logger = logging.getLogger(__name__)
        
        # Initialize LLM client
        llm_config = config.get_llm_config()
        api_key = llm_config.get("api_key")

        if not api_key:
            model_type = config.llm_type.upper()
            print(f"❌ {model_type} API key not found. Please set it with:")
            if config.llm_type == "deepseek":
                print("export DEEPSEEK_API_KEY='your-deepseek-key-here'")
            elif config.llm_type == "gpt":
                print("export OPENAI_API_KEY='your-openai-key-here'")
            elif config.llm_type == "anthropic":
                print("export ANTHROPIC_API_KEY='your-anthropic-key-here'")
            sys.exit(1)

        llm_client = get_llm_client(llm_config)
        # Set log output directory on client instance (avoids global env var)
        llm_client.log_output_dir = session_output_dir
        
        # Initialize coordinator
        coordinator = RegionBasedCoordinator(
            llm_client=llm_client,
            project_root=args.project_root,
            debug=args.debug,
            output_dir=session_output_dir,
            config=config
        )
        
        # Load chains
        chains = load_chains(args.chains_file)
        
        # Check if chains were loaded successfully
        if not chains:
            print("❌ No chains available for analysis")
            if args.chains_file:
                print(f"   Failed to load chains from: {args.chains_file}")
            else:
                print("   No chains file provided")
            sys.exit(1)
        
        if args.interactive:
            # Interactive mode
            chain_idx = select_chain_interactive(chains)
            selected_chain = chains[chain_idx]
            
            analysis_mode = "early_stopping"
            print(f"\nAnalyzing chain {chain_idx} ({analysis_mode})...")
            

            result = coordinator.analyze_chain_with_early_stopping(
                selected_chain,
                chain_idx,
            )

            print_analysis_summary(result)

        elif args.batch:
            analysis_mode = "early_stopping"
            print(f"Running batch analysis on {min(len(chains), args.max_chains)} chains ({analysis_mode})...")
            
            # Create global tracker - support resume and rebuild
            if args.rebuild:
                session_name = f"rebuilt_{int(time.time())}"
                print(f"🔄 Rebuild session: {session_name}")
                global_tracker = GlobalAnalysisTracker(output_dir=session_output_dir, session_name=session_name)
                global_tracker.rebuild_from_chain_dirs(args.rebuild)
                
                # Only generate report, no new analysis
                global_tracker.generate_reports()
                global_tracker.print_final_summary()
                return
                
            elif args.resume:
                session_name = args.resume
                print(f"📂 Resume session: {session_name}")
            else:
                session_name = f"batch_{int(time.time())}"
                print(f"🆕 Create new session: {session_name}")
            
            global_tracker = GlobalAnalysisTracker(output_dir=session_output_dir, session_name=session_name)
            
            # Pass global tracker to coordinator
            coordinator.global_tracker = global_tracker
            
            # Only early stopping analysis is supported now
            results = coordinator.batch_analyze_chains_with_early_stopping(
                chains,
                max_chains=args.max_chains,
            )
            
            # Generate global report
            global_tracker.generate_reports()
            global_tracker.print_final_summary()
            
            # Generate summary (keep original summary logic)
            summary = coordinator.get_analysis_summary(results)
            
            print("\n" + "="*80)
            print("BATCH ANALYSIS SUMMARY")
            print("="*80)
            print(f"Total Chains: {summary['total_chains']}")
            print(f"Successful Chains: {summary['successful_chains']}")
            print(f"Feasible Chains (SAT(Φ(π)) — exploitable per paper §3.5): {summary['feasible_chains']}")
            print(f"Success Rate: {summary['success_rate']:.2%}")
            print(f"Total Analysis Time: {summary['total_analysis_time']:.2f}s")
            print(f"Average Analysis Time: {summary['average_analysis_time']:.2f}s")

            print(f"\nVerdict Distribution:")
            for verdict, count in summary['verdict_distribution'].items():
                verdict_desc = {
                    "FEASIBLE": "SAT(Φ(π)) — exploitable",
                    "NOT_FEASIBLE": "UNSAT(Φ(π)) — solver pruned",
                    "NOT_REACHABLE": "Stage-2 LLM declared unreachable",
                    "EARLY_STOP": "Stage-2 early-stop pruning",
                    "ERROR": "analysis error"
                }.get(verdict, verdict)
                print(f"  {verdict}: {count} ({verdict_desc})")
            
            # Save results (now saves to chain-specific directories)
            save_results(results, session_output_dir)
        
        else:
            # Single chain mode (default)
            chain_idx = 0
            selected_chain = chains[chain_idx]

            print(f"Analyzing chain {chain_idx} in early stopping mode...")

            result = coordinator.analyze_chain_with_early_stopping(
                selected_chain,
                chain_idx,
            )

            print_analysis_summary(result)
        
        # Print usage summary
        llm_client.print_usage_summary()
        
    except KeyboardInterrupt:
        print("\n⛔ Analysis interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error in main: {e}")
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main() 
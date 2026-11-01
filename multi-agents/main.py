#!/usr/bin/env python3
"""Run resumable GadgetHunter analysis on candidate chains produced by Flash."""

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path
from uuid import uuid4


def build_parser():
    parser = argparse.ArgumentParser(description="GadgetHunter Java deserialization chain analysis")
    parser.add_argument("--config", "-c", help="JSON configuration file")
    parser.add_argument("--project-root", "-p", help="Directory containing matching Java sources")
    parser.add_argument("--chains-file", "-f", help="Candidate chains from the modified Flash backend")
    parser.add_argument("--debug", "-d", action="store_true", default=None)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--batch", "-b", action="store_true", help="Analyze all chains unless --max-chains is set")
    mode.add_argument("--interactive", "-i", action="store_true", help="Select one chain interactively")
    parser.add_argument("--chain-index", type=int, default=0, help="Zero-based index for a single-chain run")
    parser.add_argument("--max-chains", "-m", type=int, help="Batch limit; 0 means all (default)")
    parser.add_argument("--model", help="Override the configured model")
    parser.add_argument("--output-dir", help="Parent directory for new runs")
    parser.add_argument("--solver-timeout", type=int, help="Seconds allowed per solver process")
    parser.add_argument("--java-home", help="Target JDK home; enables the subtype oracle for sound cast feasibility")
    parser.add_argument("--target-classpath", action="append", default=[],
                        help="Target JAR/dir on the analysed classpath (repeatable); feeds the subtype oracle")
    parser.add_argument("--deserial-filter",
                        help="Deserialization class filter: a JEP 290 pattern string or a file; "
                             "overrides auto-extraction from the classpath")
    parser.add_argument("--resume", "-r", help="Existing run directory; inputs and settings must match")
    parser.add_argument("--rebuild", help="Rebuild legacy reports from a results directory without API calls")
    parser.add_argument("--check", action="store_true", help="Validate inputs and show duplicate counts without API calls")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        from tools.core.config import Config, load_config
        from tools.analysis.chain_parser import parse_chains_file, validate_chain_file
        from tools.analysis.scan_session import ScanSession, digest, scan_identity

        if args.rebuild:
            from utils.global_analysis_tracker import GlobalAnalysisTracker
            root = Path(args.rebuild).resolve()
            if not root.is_dir():
                raise ValueError(f"Results directory does not exist: {root}")
            tracker = GlobalAnalysisTracker(str(root), "rebuilt")
            tracker.rebuild_from_chain_dirs(str(root))
            tracker.generate_reports()
            return 0
        if not args.chains_file or not args.project_root:
            parser.error("--chains-file and --project-root are required for analysis")
        config = load_config(args.config) if args.config else Config()
        for arg, field in (("debug", "debug"), ("model", "llm_model"), ("output_dir", "output_dir"),
                           ("max_chains", "max_chains"), ("solver_timeout", "solver_timeout"),
                           ("java_home", "java_home")):
            value = getattr(args, arg)
            if value is not None:
                setattr(config, field, value)
        if getattr(args, "target_classpath", None):
            config.target_classpath = args.target_classpath
        if getattr(args, "deserial_filter", None):
            config.deserial_filter = args.deserial_filter
        if config.max_chains < 0 or config.solver_timeout <= 0:
            raise ValueError("--max-chains must be nonnegative and --solver-timeout must be positive")
        config.set_project_info(str(Path(args.project_root).resolve()))
        config.configure_logging()
        validation = validate_chain_file(args.chains_file)
        if not validation["valid"] or not validation.get("total_chains"):
            raise ValueError(f"Invalid or empty chains file: {validation}")
        chains = parse_chains_file(args.chains_file)
        identity = scan_identity(chains, config.project_path, config)
        indices = None
        if not args.batch:
            if args.interactive:
                for index, chain in enumerate(chains):
                    print(f"{index}: {len(chain)} edges; {chain[0]}")
                args.chain_index = int(input("Chain index: "))
            if not 0 <= args.chain_index < len(chains):
                raise ValueError("--chain-index is outside the chains file")
            indices = [args.chain_index]
        selected = [chains[i] for i in indices] if indices is not None else chains[:config.max_chains or None]
        unique = len({digest(chain) for chain in selected})
        print(f"Selected {len(selected)} chains ({unique} unique); {identity['sources']['files']} Java source files")
        if args.check:
            return 0
        llm_config = config.get_llm_config()
        if not llm_config.get("api_key"):
            raise ValueError(f"API key missing for provider {config.llm_type}; set it in the environment")

        from tools.core import get_llm_client
        from agents.region_based_coordinator import RegionBasedCoordinator
        from utils.global_analysis_tracker import GlobalAnalysisTracker

        if args.resume:
            output = Path(args.resume).resolve()
            if not output.is_dir():
                raise ValueError(f"Resume directory does not exist: {output}")
        else:
            run_name = f"{datetime.now():%Y%m%d_%H%M%S}_{config.project_name}_{uuid4().hex[:8]}"
            output = Path(config.output_dir).resolve() / run_name
        client = get_llm_client(llm_config)
        coordinator = RegionBasedCoordinator(client, config.project_path, config.debug, str(output), config=config)
        session = ScanSession(output, identity, resume=bool(args.resume))
        print(f"Results: {output}")
        # Checkpoints own resume decisions; the tracker records phase tokens and costs.
        coordinator.global_tracker = GlobalAnalysisTracker(str(output), "usage")
        results = session.run(chains, coordinator, config.max_chains, indices)
        for result in results:
            print(f"Chain {result['chain_id']}: {result['conclusion']['verdict']}")
        print(f"Execution: {dict(session.stats)}; reused LLM requests: {coordinator.semantic_agent.cache_hits}")
        client.print_usage_summary()
        verdicts = {r["conclusion"]["verdict"] for r in results}
        return 1 if "ERROR" in verdicts else 2 if "UNKNOWN" in verdicts else 0
    except KeyboardInterrupt:
        print("Analysis interrupted; completed chains are saved. Resume using the same inputs and --resume RUN_DIR.", file=sys.stderr)
        return 130
    except Exception as exc:
        logging.getLogger(__name__).error("Analysis failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())

"""
Region Based Coordinator: 
Unified coordinator using unified agents and tools
"""

import time
import os
import sys
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from .base_agent import BaseAgent
from tools.analysis.outcomes import InconclusiveAnalysis
from .region_analyzer_agent import RegionAnalyzerAgent
from .semantic_reachability_agent import SemanticReachabilityAgent
from tools.core import LLMClient
from .path_constraint_agent import PathConstraintAgent

# Add utils path for importing global tracker
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.global_analysis_tracker import GlobalAnalysisTracker


@dataclass
class AnalysisResult:
    """Complete analysis result for a gadget chain (paper §3.2)."""
    chain_id: int
    original_chain: List[str]
    region_analysis: Dict[str, Any]
    semantic_analysis: Dict[str, Any]
    feasibility_analysis: Dict[str, Any]
    conclusion: Dict[str, Any]
    analysis_time: float = 0.0
    error: Optional[str] = None


class RegionBasedCoordinator(BaseAgent):
    """
    Region Based Coordinator using unified agents
    
    Provides unified interface for complete gadget chain analysis
    """
    
    def __init__(self, llm_client: LLMClient, project_root: Optional[str] = None, debug: bool = False, output_dir: str = "results", global_tracker: Optional[GlobalAnalysisTracker] = None, config=None):
        super().__init__(llm_client, debug)
        
        # Use default project root if not provided
        root_path = project_root or "/default/path"
        self.output_dir = output_dir
        self.global_tracker = global_tracker  # Optional global tracker
        self.config = config  # Save config object for project name access
        
        # Initialize agents with unified output directory
        self.region_analyzer = RegionAnalyzerAgent(llm_client, root_path, debug)
        self.semantic_agent = SemanticReachabilityAgent(llm_client, root_path, debug)
        self.path_constraint_agent = PathConstraintAgent(llm_client, debug, output_dir=output_dir, config=config)
        
        self.semantic_agent.cache_size = getattr(config, "llm_cache_size", 256)
        if config is not None:
            self.region_analyzer.code_extractor.parser.extract_javadoc = config.extract_javadoc
            self.semantic_agent.code_extractor.parser.extract_javadoc = config.extract_javadoc
        self.path_constraint_agent.solver_timeout = getattr(config, "solver_timeout", 30)
        self.path_constraint_agent.max_fix_attempts = getattr(config, "max_fix_attempts", 3)
        self.logger.info("Coordinator initialized with unified agents")
    
    def _setup_chain_output_directory(self, chain_id: int) -> str:
        """Setup chain-specific output directory and update agents' output directories"""
        # Create chain-specific directory
        chain_dir = os.path.join(self.output_dir, f"chain{chain_id}")
        os.makedirs(chain_dir, exist_ok=True)
        
        # Create subdirectories for this chain
        subdirs = ["analysis_results", "llm_logs", "z3_debug"]
        for subdir in subdirs:
            os.makedirs(os.path.join(chain_dir, subdir), exist_ok=True)

        # Update agents' output directories to use chain-specific paths
        self.path_constraint_agent.output_dir = chain_dir
        
        # Set log output directory on LLM client (avoids global env var pollution)
        self.llm_client.log_output_dir = chain_dir
        
        self.logger.info(f"Setup chain-specific output directory: {chain_dir}")
        return chain_dir
    
    def analyze_chain_with_early_stopping(self, chain: List[str], chain_id: int) -> AnalysisResult:
        """
        Analyze a candidate gadget chain end-to-end (paper §3.2 pipeline).

        Stages:
        1. Region Analysis (paper §3.4 Algorithm 1)
        2. Region Edge Semantic Reachability (paper §3.4.3, with early stop)
        3. Code Summary and Constraint Extraction (paper §3.5.1)
        4. SMT Path Feasibility (paper §3.5.2)
        5. Generate Conclusion (verdict ∈ {FEASIBLE, NOT_FEASIBLE, EARLY_STOP,
           UNKNOWN, ERROR}; FEASIBLE means SAT(Φ(π)), i.e. exploitable per paper §3.5).
        """
        start_time = time.time()
        
        # Record baseline token usage at the start of this chain
        initial_usage = self.llm_client.get_usage_summary()
        initial_tokens = {
            "prompt_tokens": initial_usage.total_prompt_tokens,
            "completion_tokens": initial_usage.total_completion_tokens,
            "total_tokens": initial_usage.total_tokens
        }
        initial_cost = initial_usage.total_cost_usd
        
        # Per-phase token tracking - fine-grained phase breakdown (paper §5.4)
        phase_tokens = {
            "semantic_reachability": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "code_summary_and_constraints": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "z3_constraint_solving": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }
        phase_costs = {
            "semantic_reachability": 0.0,
            "code_summary_and_constraints": 0.0,
            "z3_constraint_solving": 0.0,
        }
        
        # Notify global tracker that analysis has started (if present)
        if self.global_tracker:
            self.global_tracker.start_chain_analysis(chain_id, f"chain_{chain_id}", "")
        
        try:
            self.logger.info(f"Starting early-stopping analysis for chain {chain_id}")
            
            # Setup chain-specific output directory
            chain_output_dir = self._setup_chain_output_directory(chain_id)
            
            # Update output directory in the tracker
            if self.global_tracker and chain_id in self.global_tracker.records:
                self.global_tracker.records[chain_id].output_dir = chain_output_dir
            
            # Step 1: Region Analysis
            self.logger.info("Step 1: Region Analysis")
            region_analysis = self.region_analyzer.analyze_gadget_chain(chain, chain_id)
            
            # Step 2: Check reachability of each region edge (early stopping check)
            self.logger.info("Step 2: Region Edge Reachability Analysis")
            
            # Extract region edges and perform reachability analysis
            region_edges = self._extract_region_edges_with_source(region_analysis)
            semantic_reachability_start_usage = self.llm_client.get_usage_summary()
            semantic_reachability_start_cost = semantic_reachability_start_usage.total_cost_usd
            
            semantic_results = []
            for i, edge_info in enumerate(region_edges):
                self.logger.info(f"Analyzing region edge {i}: {edge_info['transition_type']}")
                
                reachability_result = self.semantic_agent.analyze_region_edge_reachability(edge_info, i, chain_id)
                
                semantic_results.append({"edge_index": i, **reachability_result})
                if reachability_result.get("error"):
                    raise RuntimeError(reachability_result["error"])
                if reachability_result.get("reachable") is None:
                    raise InconclusiveAnalysis(reachability_result.get("reasoning", "Reachability is unknown"))
                # Only an explicit negative decision can prune the chain.
                if reachability_result.get('reachable') is False:
                    self.logger.info(f"Early stopping at region edge {i}: {reachability_result.get('reasoning', 'Unreachable')}")
                    early_stop_result = self._create_early_stop_result(chain_id, chain, region_analysis, edge_info, i, reachability_result, time.time() - start_time)
                    
                    # Record token usage for semantic reachability phase (early stop case)
                    semantic_reachability_end_usage = self.llm_client.get_usage_summary()
                    phase_tokens["semantic_reachability"] = {
                        "prompt_tokens": semantic_reachability_end_usage.total_prompt_tokens - semantic_reachability_start_usage.total_prompt_tokens,
                        "completion_tokens": semantic_reachability_end_usage.total_completion_tokens - semantic_reachability_start_usage.total_completion_tokens,
                        "total_tokens": semantic_reachability_end_usage.total_tokens - semantic_reachability_start_usage.total_tokens
                    }
                    phase_costs["semantic_reachability"] = semantic_reachability_end_usage.total_cost_usd - semantic_reachability_start_cost
                    
                    # Notify global tracker that early-stop analysis is complete
                    if self.global_tracker:
                        # Calculate token usage delta for this chain
                        current_usage = self.llm_client.get_usage_summary()
                        chain_token_usage = {
                            "prompt_tokens": current_usage.total_prompt_tokens - initial_tokens["prompt_tokens"],
                            "completion_tokens": current_usage.total_completion_tokens - initial_tokens["completion_tokens"],
                            "total_tokens": current_usage.total_tokens - initial_tokens["total_tokens"]
                        }
                        chain_cost = current_usage.total_cost_usd - initial_cost

                        # Prepare early-stop analysis result data
                        analysis_data = {
                            "conclusion": early_stop_result.conclusion,
                        }
                        self.global_tracker.complete_chain_analysis(
                            chain_id, 
                            analysis_data,
                            chain_token_usage,
                            chain_cost,
                            phase_tokens,
                            phase_costs
                        )
                    
                    return early_stop_result
            
            # Record token usage after semantic reachability phase completion
            semantic_reachability_end_usage = self.llm_client.get_usage_summary()
            phase_tokens["semantic_reachability"] = {
                "prompt_tokens": semantic_reachability_end_usage.total_prompt_tokens - semantic_reachability_start_usage.total_prompt_tokens,
                "completion_tokens": semantic_reachability_end_usage.total_completion_tokens - semantic_reachability_start_usage.total_completion_tokens,
                "total_tokens": semantic_reachability_end_usage.total_tokens - semantic_reachability_start_usage.total_tokens
            }
            phase_costs["semantic_reachability"] = semantic_reachability_end_usage.total_cost_usd - semantic_reachability_start_cost
            
            self.logger.info("All region edges are reachable, proceeding to constraint analysis")
            
            # Step 3: Code Summary and Constraint Extraction
            self.logger.info("Step 3: Code Summary and Constraint Extraction")
            code_summary_start_usage = self.llm_client.get_usage_summary()
            code_summary_start_cost = code_summary_start_usage.total_cost_usd
            
            region_analysis = self._perform_detailed_constraint_analysis(region_analysis)
            
            # Record token usage for code summary and constraint extraction phase
            code_summary_end_usage = self.llm_client.get_usage_summary()
            phase_tokens["code_summary_and_constraints"] = {
                "prompt_tokens": code_summary_end_usage.total_prompt_tokens - code_summary_start_usage.total_prompt_tokens,
                "completion_tokens": code_summary_end_usage.total_completion_tokens - code_summary_start_usage.total_completion_tokens,
                "total_tokens": code_summary_end_usage.total_tokens - code_summary_start_usage.total_tokens
            }
            phase_costs["code_summary_and_constraints"] = code_summary_end_usage.total_cost_usd - code_summary_start_cost

            # Step 4: Z3 Constraint Solving (includes constraint script generation and solving)
            self.logger.info("Step 4: Z3 Constraint Solving")
            z3_start_usage = self.llm_client.get_usage_summary()
            z3_start_cost = z3_start_usage.total_cost_usd
            
            feasibility_analysis = self._analyze_feasibility(region_analysis)
            
            # Record token usage for Z3 constraint solving phase (including script generation and repair)
            z3_end_usage = self.llm_client.get_usage_summary()
            phase_tokens["z3_constraint_solving"] = {
                "prompt_tokens": z3_end_usage.total_prompt_tokens - z3_start_usage.total_prompt_tokens,
                "completion_tokens": z3_end_usage.total_completion_tokens - z3_start_usage.total_completion_tokens,
                "total_tokens": z3_end_usage.total_tokens - z3_start_usage.total_tokens
            }
            phase_costs["z3_constraint_solving"] = z3_end_usage.total_cost_usd - z3_start_cost
            
            # Step 5: Generate Conclusion (verdict from SMT only, paper §3.5)
            self.logger.info("Step 5: Generate Conclusion")
            conclusion = self._generate_conclusion(region_analysis, feasibility_analysis)

            analysis_time = time.time() - start_time

            result = AnalysisResult(
                chain_id=chain_id,
                original_chain=chain,
                region_analysis=region_analysis,
                semantic_analysis={"early_stopping_used": True, "reachability_validated": True, "edges": semantic_results},
                feasibility_analysis=feasibility_analysis,
                conclusion=conclusion,
                analysis_time=analysis_time
            )
            
            # Notify global tracker that analysis is complete
            if self.global_tracker:
                # Calculate token usage delta for this chain
                current_usage = self.llm_client.get_usage_summary()
                chain_token_usage = {
                    "prompt_tokens": current_usage.total_prompt_tokens - initial_tokens["prompt_tokens"],
                    "completion_tokens": current_usage.total_completion_tokens - initial_tokens["completion_tokens"],
                    "total_tokens": current_usage.total_tokens - initial_tokens["total_tokens"]
                }
                chain_cost = current_usage.total_cost_usd - initial_cost
                
                # Prepare complete analysis result data
                analysis_data = {
                    "conclusion": conclusion,
                }
                self.global_tracker.complete_chain_analysis(
                    chain_id, 
                    analysis_data,
                    chain_token_usage,
                    chain_cost,
                    phase_tokens,
                    phase_costs
                )
            
            return result
            
        except InconclusiveAnalysis as e:
            result = AnalysisResult(
                chain_id, chain, locals().get("region_analysis", {}),
                {"reachability_validated": False, "reason": str(e), "edges": locals().get("semantic_results", [])}, {},
                {"verdict": "UNKNOWN", "reasoning": str(e)}, time.time() - start_time,
            )
            if self.global_tracker:
                usage = self.llm_client.get_usage_summary()
                self.global_tracker.complete_chain_analysis(
                    chain_id, {"conclusion": result.conclusion},
                    {"prompt_tokens": usage.total_prompt_tokens - initial_tokens["prompt_tokens"],
                     "completion_tokens": usage.total_completion_tokens - initial_tokens["completion_tokens"],
                     "total_tokens": usage.total_tokens - initial_tokens["total_tokens"]},
                    usage.total_cost_usd - initial_cost,
                )
            return result

        except Exception as e:
            self.logger.error(f"Error in early-stopping analysis for chain {chain_id}: {e}")
            analysis_time = time.time() - start_time
            
            # Notify global tracker that analysis failed
            if self.global_tracker:
                self.global_tracker.fail_chain_analysis(chain_id, str(e))
            
            return AnalysisResult(
                chain_id=chain_id,
                original_chain=chain,
                region_analysis={},
                semantic_analysis={},
                feasibility_analysis={},
                conclusion={"verdict": "ERROR", "reasoning": str(e)},
                analysis_time=analysis_time,
                error=str(e)
            )
    
    def _analyze_feasibility(self, region_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze feasibility using path constraint agent"""
        try:
            chain_id = region_analysis.get("chain_id", 0)
            
            feasibility_result = self.path_constraint_agent.verify_path_feasibility(
                region_analysis, chain_id
            )
            
            return {
                "solver_status": feasibility_result.solver_status.value if hasattr(feasibility_result.solver_status, 'value') else str(feasibility_result.solver_status),
                "is_feasible": feasibility_result.is_feasible,
                "constraint_count": feasibility_result.constraint_count,
                "execution_time": feasibility_result.execution_time,
                "z3_model": feasibility_result.z3_model,
                "constraints": [constraint.to_dict() if hasattr(constraint, 'to_dict') else str(constraint) for constraint in feasibility_result.constraints],
                # Paper §3.5.1 four-tuple ⟨Vars, Flow, Guard, Runtime⟩ exposed for audit.
                "json_constraints": getattr(feasibility_result, "json_constraints", {}),
                "error_message": feasibility_result.error_message
            }
            
        except Exception as e:
            self.logger.error(f"Error in feasibility analysis: {e}")
            return {
                "solver_status": "ERROR",
                "is_feasible": False,
                "constraint_count": 0,
                "execution_time": 0.0,
                "error_message": str(e)
            }
    
    def _generate_conclusion(self, region_analysis: Dict[str, Any], 
                           feasibility_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate conclusion based on semantic reachability (Step 2) and constraint feasibility (Step 4)"""
        status = str(feasibility_analysis.get("solver_status", "unknown")).lower()
        verdict, reasoning = {
            "sat": ("FEASIBLE", "The extracted constraints are satisfiable; payload execution is not verified."),
            "unsat": ("NOT_FEASIBLE", "The extracted constraints are unsatisfiable."),
            "unknown": ("UNKNOWN", "The solver could not establish feasibility."),
            "error": ("ERROR", "Constraint analysis failed."),
        }.get(status, ("UNKNOWN", "No recognized solver result."))
        detail = feasibility_analysis.get("error_message")
        return {
            "verdict": verdict,
            "reasoning": f"{reasoning} {detail}" if detail else reasoning,
            "semantic_reachable": True,
            "feasible": True if status == "sat" else False if status == "unsat" else None,
            "solver_status": status,
            "constraint_count": feasibility_analysis.get("constraint_count", 0),
        }

    def batch_analyze_chains_with_early_stopping(self, chains: List[List[str]], max_chains: int = 10) -> List[AnalysisResult]:
        """Analyze multiple chains in batch with early stopping"""
        results = []

        for i, chain in enumerate(chains[:max_chains]):
            # Simple checkpoint/resume check
            if self.global_tracker and self.global_tracker.is_chain_completed(i):
                print(f"Chain {i} already completed, skipping")
                continue

            try:
                result = self.analyze_chain_with_early_stopping(chain, i)
                results.append(result)
                
                # Provide more detailed log information
                verdict = result.conclusion.get('verdict', 'UNKNOWN')
                semantic_analysis = result.semantic_analysis if hasattr(result, 'semantic_analysis') else {}
                early_stop = semantic_analysis.get("early_stop", False)
                
                if early_stop:
                    failed_edge = semantic_analysis.get("failed_edge", {})
                    self.logger.info(f"Chain {i} early stopped at edge {failed_edge.get('edge_index', 'Unknown')} (verdict: {verdict})")
                else:
                    self.logger.info(f"Chain {i} completed analysis (verdict: {verdict})")
                    
            except Exception as e:
                self.logger.error(f"Failed to analyze chain {i}: {e}")
                results.append(AnalysisResult(
                    chain_id=i,
                    original_chain=chain,
                    region_analysis={},
                    semantic_analysis={},
                    feasibility_analysis={},
                    conclusion={"verdict": "ERROR", "reasoning": str(e)},
                    error=str(e)
                ))
        
        return results
    
    def get_analysis_summary(self, results: List[AnalysisResult]) -> Dict[str, Any]:
        """Aggregate per-chain verdicts into batch-level statistics."""
        total_chains = len(results)
        successful_chains = len([r for r in results if r.conclusion.get("verdict") not in {"ERROR", "UNKNOWN"}])
        feasible_chains = len([r for r in results if r.conclusion.get("verdict") == "FEASIBLE"])

        verdict_counts: Dict[str, int] = {}
        for result in results:
            verdict = result.conclusion.get("verdict", "UNKNOWN")
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1

        total_time = sum(r.analysis_time for r in results)
        avg_time = total_time / total_chains if total_chains > 0 else 0

        return {
            "total_chains": total_chains,
            "successful_chains": successful_chains,
            "feasible_chains": feasible_chains,  # Z3-SAT chains == exploitable per paper §3.5
            "verdict_distribution": verdict_counts,
            "total_analysis_time": total_time,
            "average_analysis_time": avg_time,
            "success_rate": successful_chains / total_chains if total_chains > 0 else 0
        }
    
    def _extract_region_edges_with_source(self, region_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract region edges, including raw call edges and source method code

        Args:
            region_analysis: Region analysis result

        Returns:
            List of region edge info with source code
        """
        regions = region_analysis.get("regions", [])
        if len(regions) < 2:
            return []
        
        region_edges = []
        
        for i in range(len(regions) - 1):
            from_region = regions[i]
            to_region = regions[i + 1]
            
            # Get raw call edge strings for the region edge
            from_gadgets = from_region.get("gadgets", [])
            to_gadgets = to_region.get("gadgets", [])
            
            if not from_gadgets or not to_gadgets:
                continue
            
            # Find the call edge connecting the two regions
            connecting_gadget = from_gadgets[-1]  # Connecting gadget
            
            # Extract source method code (the caller 'a' in call edge a->b)
            source_code = self._extract_source_code_from_gadget(connecting_gadget)
            
            edge_info = {
                "edge_id": i,
                "from_region_id": from_region.get("region_id", i),
                "to_region_id": to_region.get("region_id", i + 1),
                "raw_call_edge": connecting_gadget,
                "source_method_code": source_code,
                "transition_type": f"{from_region.get('region_type', 'unknown')} -> {to_region.get('region_type', 'unknown')}",
                "from_gadgets": from_gadgets,
                "to_gadgets": to_gadgets
            }
            
            region_edges.append(edge_info)
        
        return region_edges
    
    def _perform_detailed_constraint_analysis(self, region_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate code summaries for each gadget using LLM"""
        self.logger.info("Generating code summaries for constraint analysis...")
        
        regions = region_analysis.get("regions", [])
        total_summaries = 0

        for region in regions:
            region_id = region.get("region_id", -1)
            gadgets = region.get("gadgets", [])
            
            self.logger.info(f"Processing region {region_id} with {len(gadgets)} gadgets")
            
            for gadget_idx, gadget in enumerate(gadgets):
                if not isinstance(gadget, dict):
                    self.logger.warning(f"Skipping non-dict gadget in region {region_id}")
                    continue
                
                gadget_id = f"r{region_id}_g{gadget_idx}"
                
                gadget_info = {
                    "gadget_id": gadget_id,
                    "raw_gadget": gadget.get("raw_gadget", ""),
                    "method_signature": gadget.get("method_signature", ""),
                    "region_type": region.get("region_type", "unknown"),
                    "source_code": gadget.get("source_code"),
                    "source_extraction": gadget.get("source_extraction", {}),
                    "chain_id": region_analysis.get("chain_id", 0)  # Pass chain_id to gadget_info
                }
                
                try:
                    code_summary = self.semantic_agent.generate_gadget_code_summary(gadget_info)
                    gadget["code_summary"] = code_summary
                    total_summaries += 1
                    self.logger.info(f"Code summary for gadget {gadget_id}")
                except InconclusiveAnalysis as e:
                    gadget["code_summary"] = {"inconclusive": str(e)}
                except Exception as e:
                    raise RuntimeError(f"Code summary failed for gadget {gadget_id}: {e}") from e

        # Update metadata  
        region_analysis["analysis_metadata"]["gadget_summaries"] = total_summaries
        
        self.logger.info(f"Code summary completed: {total_summaries} summaries")
        return region_analysis
    
    def _perform_deserialization_audit(self, region_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate deserialization audits for each gadget using LLM"""
        self.logger.info("Generating deserialization audits for vulnerability analysis...")
        
        regions = region_analysis.get("regions", [])
        total_audits = 0

        for region in regions:
            region_id = region.get("region_id", -1)
            gadgets = region.get("gadgets", [])
            
            self.logger.info(f"Processing region {region_id} with {len(gadgets)} gadgets for deserialization audit")
            
            for gadget_idx, gadget in enumerate(gadgets):
                if not isinstance(gadget, dict):
                    self.logger.warning(f"Skipping non-dict gadget in region {region_id}")
                    continue
                
                gadget_id = f"r{region_id}_g{gadget_idx}"
                
                gadget_info = {
                    "gadget_id": gadget_id,
                    "raw_gadget": gadget.get("raw_gadget", ""),
                    "method_signature": gadget.get("method_signature", ""),
                    "region_type": region.get("region_type", "unknown"),
                    "source_code": gadget.get("source_code"),
                    "source_extraction": gadget.get("source_extraction", {}),
                    "chain_id": region_analysis.get("chain_id", 0)  # Pass chain_id to gadget_info
                }
                
                self.logger.info(f"Starting deserialization audit for gadget {gadget_id}")
                deserialization_audit = self.semantic_agent.generate_deserialization_audit(gadget_info)
                gadget["deserialization_audit"] = deserialization_audit
                total_audits += 1
                self.logger.info(f"✅ Completed deserialization audit for gadget {gadget_id}")

        # Update metadata  
        region_analysis["analysis_metadata"]["deserialization_audits"] = total_audits
        
        self.logger.info(f"Deserialization audit completed: {total_audits} audits")
        return region_analysis

    def _extract_source_code_from_gadget(self, gadget_input) -> str:
        """
        Extract source code from gadget - reuses SemanticReachabilityAgent logic
        
        Args:
            gadget_input: gadget string or gadget dictionary object
                       
        Returns:
            source code string
        """
        try:
            # Delegate to SemanticReachabilityAgent's unified method
            return self.semantic_agent._get_source_code_from_gadget(gadget_input, fallback_to_extraction=True)
            
        except Exception as e:
            self.logger.warning(f"Failed to extract source code from gadget: {e}")
            return "Unavailable. Infer its deserialization role based on domain knowledge."
    
    def _create_early_stop_result(self, chain_id: int, chain: List[str], region_analysis: Dict[str, Any], 
                                failed_edge: Dict[str, Any], edge_index: int, 
                                reachability_result: Dict[str, Any], analysis_time: float) -> AnalysisResult:
        """
        Create early stopping result
        
        Args:
            chain_id: Chain identifier
            chain: Original chain
            region_analysis: Region analysis result
            failed_edge: The edge that caused early stopping
            edge_index: Index of failed edge
            reachability_result: Reachability analysis result
            analysis_time: Analysis time
            
        Returns:
            AnalysisResult with early stopping information
        """
        conclusion = {
            "verdict": "EARLY_STOP",
            "reasoning": f"Chain analysis stopped at region edge {edge_index}: {reachability_result.get('reasoning', 'Unreachable')}",
            "failed_edge_index": edge_index,
            "failed_edge": failed_edge.get('raw_call_edge', 'Unknown'),
            "source_method_code": failed_edge.get('source_method_code', 'Not available'),
            "early_stop_reason": reachability_result.get('reasoning', 'Unreachable')
        }
        
        return AnalysisResult(
            chain_id=chain_id,
            original_chain=chain,
            region_analysis=region_analysis,
            semantic_analysis={"early_stop": True, "failed_edge": failed_edge, "reachability_result": reachability_result},
            feasibility_analysis={"early_stop": True, "reason": "Region edge unreachable"},
            conclusion=conclusion,
            analysis_time=analysis_time
        ) 
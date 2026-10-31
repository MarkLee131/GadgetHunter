"""
Path Constraint Agent
Z3-based constraint solving and path feasibility verification
"""

import time
import os
import re
import sys
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum

from .base_agent import BaseAgent
from tools.analysis.outcomes import InconclusiveAnalysis
from tools.core import LLMClient


class Z3SolverStatus(Enum):
    """Z3 solver status enumeration."""
    SAT = "sat"
    UNSAT = "unsat"
    UNKNOWN = "unknown"
    ERROR = "error"


@dataclass
class Z3Constraint:
    """Represents a Z3 constraint derived from region analysis."""
    constraint_id: str
    constraint_type: str
    z3_formula: str
    source_region: int
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert constraint to dictionary format"""
        return {
            "constraint_id": self.constraint_id,
            "constraint_type": self.constraint_type,
            "z3_formula": self.z3_formula,
            "source_region": self.source_region,
            "description": self.description,
            "metadata": self.metadata
        }


@dataclass
class PathFeasibilityResult:
    """Result of path feasibility analysis."""
    chain_id: int
    solver_status: Z3SolverStatus
    is_feasible: bool
    z3_model: Optional[str] = None
    execution_time: float = 0.0
    error_message: Optional[str] = None
    constraint_count: int = 0
    z3_script: Optional[str] = None
    fix_attempts: int = 0
    constraints: List = field(default_factory=list)  # Added missing constraints field
    # Aggregated four-tuple ⟨Vars, Flow, Guard, Runtime⟩ that was lowered to SMT
    # (paper §3.5.1). Surfaced so reviewers can audit which Runtime predicates
    # were actually conjoined into Φ(π).
    json_constraints: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.z3_model is None:
            self.z3_model = ""
        if self.constraints is None:
            self.constraints = []


class PathConstraintAgent(BaseAgent):
    """
    Path Constraint Agent
    Responsible for Z3-based constraint solving and path feasibility verification
    """
    
    def __init__(self, llm_client: LLMClient, debug: bool = False, output_dir: str = "results"):
        super().__init__(llm_client, debug)
        # prompt_manager is now initialized in BaseAgent
        self.max_fix_attempts = 3
        self.solver_timeout = 30
        self.output_dir = output_dir
        
    def verify_path_feasibility(self, region_analysis: Dict[str, Any], 
                              chain_id: int) -> PathFeasibilityResult:
        """
        Verify path feasibility using Z3 solver.
        
        This is the main entry point that orchestrates the verification process.
        """
        try:
            self.logger.info(f"Starting path feasibility verification for chain {chain_id}")
            start_time = time.time()

            # Aggregate the four-tuple ⟨Vars, Flow, Guard, Runtime⟩ once so we
            # can both feed the Z3 translator and persist it in the result JSON.
            json_constraints = self._convert_region_analysis_to_json(region_analysis)
            z3_script = self._generate_z3_from_json_constraints(json_constraints)

            # Save script for debugging
            self._save_z3_script(z3_script, chain_id, "initial")

            # Solve constraints
            solver_result = self._solve_z3_constraints(z3_script, chain_id)

            # Build final result
            execution_time = time.time() - start_time
            result = self._build_feasibility_result(chain_id, solver_result, z3_script, execution_time)
            result.json_constraints = json_constraints
            return result
            
        except InconclusiveAnalysis as e:
            return PathFeasibilityResult(chain_id, Z3SolverStatus.UNKNOWN, False, error_message=str(e),
                                         json_constraints=locals().get("json_constraints", {}))
        except Exception as e:
            self.logger.error(f"Error verifying path feasibility: {e}")
            return self._build_error_result(chain_id, e)
    
    def _generate_z3_script(self, region_analysis: Dict[str, Any]) -> str:
        """Generate Z3 script from region analysis. Single responsibility: script generation."""
        return self._build_z3_script_with_python_translator(region_analysis)
    
    def _solve_z3_constraints(self, z3_script: str, chain_id: int) -> Dict[str, Any]:
        """Solve Z3 constraints. Single responsibility: constraint solving."""
        return self._execute_z3_with_fixing(z3_script, chain_id)
    
    def _build_feasibility_result(self, chain_id: int, solver_result: Dict[str, Any], 
                                z3_script: str, execution_time: float) -> PathFeasibilityResult:
        """Build successful feasibility result. Single responsibility: result construction."""
        solver_status = self._parse_solver_status(solver_result.get("status", "unknown"))
        
        return PathFeasibilityResult(
            chain_id=chain_id,
            solver_status=solver_status,
            is_feasible=solver_result.get("status") == "sat",
            z3_model=solver_result.get("model"),
            execution_time=execution_time,
            constraint_count=solver_result.get("constraint_count", 0),
            error_message=solver_result.get("error"),
            z3_script=solver_result.get("final_script", z3_script),
            fix_attempts=solver_result.get("fix_attempts", 0),
            constraints=[]
        )
    
    def _parse_solver_status(self, status_str: str) -> Z3SolverStatus:
        """Parse solver status string to enum. Single responsibility: status parsing."""
        status_map = {
            "sat": Z3SolverStatus.SAT,
            "unsat": Z3SolverStatus.UNSAT, 
            "error": Z3SolverStatus.ERROR,
        }
        return status_map.get(status_str, Z3SolverStatus.UNKNOWN)
    
    def _build_error_result(self, chain_id: int, error: Exception) -> PathFeasibilityResult:
        """Build error result. Single responsibility: error result construction."""
        return PathFeasibilityResult(
            chain_id=chain_id,
            solver_status=Z3SolverStatus.ERROR,
            is_feasible=False,
            error_message=str(error),
            constraint_count=0,
            constraints=[]
        )


    
    def _execute_z3_solver(self, z3_script: str) -> Dict[str, Any]:
        """Execute Z3 script and return results."""
        import tempfile
        import subprocess

        start_time = time.monotonic()
        try:
            with tempfile.TemporaryDirectory(prefix="gadgethunter-z3-") as temp_dir:
                script = os.path.join(temp_dir, "constraints.py")
                with open(script, "w", encoding="utf-8") as handle:
                    handle.write(z3_script)
                result = subprocess.run(
                    [sys.executable, script], capture_output=True, text=True,
                    timeout=self.solver_timeout,
                )
            output = result.stdout.strip()
            statuses = re.findall(r"^(?:Enhanced Z3 )?Result: (sat|unsat|unknown)$", output, re.M)
            status = statuses[0] if len(statuses) == 1 else "error"
            error = None
            if result.returncode != 0:
                status, error = "error", result.stderr.strip() or f"Solver exited with {result.returncode}"
            elif status == "error":
                error = "Missing or ambiguous solver status"
            count = re.search(r"^Constraint count: (\d+)$", output, re.M)
            model = re.search(r"^(?:Logical )?Model: ([\s\S]*)", output, re.M)
            return {
                "status": status, "model": model[1] if model and status == "sat" else None,
                "constraint_count": int(count[1]) if count else 0,
                "error": error, "execution_time": time.monotonic() - start_time,
                "stdout": output, "stderr": result.stderr, "return_code": result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"status": "unknown", "error": f"Solver timed out after {self.solver_timeout}s",
                    "timed_out": True, "execution_time": time.monotonic() - start_time}
        except Exception as e:
            return {"status": "error", "error": str(e), "execution_time": time.monotonic() - start_time}

    def _execute_z3_with_fixing(self, z3_script: str, chain_id: int) -> Dict[str, Any]:
        """Execute Z3 script with iterative LLM-based fixing"""
        current_script = z3_script
        fix_attempts = 0
        
        for attempt in range(self.max_fix_attempts + 1):
            self.logger.info(f"Z3 execution attempt {attempt + 1}")
            
            # Execute current script
            result = self._execute_z3_solver(current_script)
            
            # Unknown and timeout are not script defects; do not spend API calls repairing them.
            if result.get("status") == "unknown" or (result.get("return_code") == 0 and result.get("status") != "error"):
                result["final_script"] = current_script
                result["fix_attempts"] = fix_attempts
                
                # Save Z3 model output if satisfiable
                if result.get("status") == "sat":
                    try:
                        model_file = self._save_z3_model_output(
                            z3_output=result.get("stdout", ""),
                            chain_id=chain_id
                        )
                        result["model_file"] = model_file
                    except Exception as e:
                        self.logger.error(f"Failed to save Z3 model output: {e}")
                
                return result
            
            # If we've reached max attempts, return the last error
            if attempt >= self.max_fix_attempts:
                self.logger.warning(f"Max Z3 fix attempts ({self.max_fix_attempts}) reached")
                result["final_script"] = current_script
                result["fix_attempts"] = fix_attempts
                
                # Save Z3 model output if the last attempt was satisfiable
                if result.get("status") == "sat":
                    try:
                        model_file = self._save_z3_model_output(
                            z3_output=result.get("stdout", ""),
                            chain_id=chain_id
                        )
                        result["model_file"] = model_file
                    except Exception as e:
                        self.logger.error(f"Failed to save Z3 model output: {e}")
                
                return result
            
            # Try to fix the script using LLM
            self.logger.info(f"Attempting to fix Z3 script (attempt {attempt + 1})")
            fixed_script = self._fix_z3_script_with_llm(
                current_script, 
                result.get("stderr", ""), 
                result.get("stdout", ""),
                chain_id,
                attempt + 1
            )
            
            if fixed_script and fixed_script != current_script:
                # Fixed script is already saved in fixes/ folder by _fix_z3_script_with_llm
                self.logger.info(f"Using fixed Z3 script from attempt {attempt + 1}")
                
                current_script = fixed_script
                fix_attempts += 1
            else:
                self.logger.warning("LLM could not provide a valid fix")
                break
        
        # Return the last result
        result["final_script"] = current_script
        result["fix_attempts"] = fix_attempts
        
        # Save Z3 model output if the final result is satisfiable
        if result.get("status") == "sat":
            try:
                model_file = self._save_z3_model_output(
                    z3_output=result.get("stdout", ""),
                    chain_id=chain_id
                )
                result["model_file"] = model_file
            except Exception as e:
                self.logger.error(f"Failed to save Z3 model output: {e}")
        
        # Save the final successful script with clear marking
        if result.get("status") == "sat" and current_script:
            try:
                final_script_path = self._save_final_z3_script(current_script, chain_id, result.get("status"))
                result["final_script_file"] = final_script_path
                self.logger.info(f"Saved FINAL successful Z3 script to: {final_script_path}")
            except Exception as e:
                self.logger.error(f"Failed to save final Z3 script: {e}")
        
        return result
    
    def _fix_z3_script_with_llm(self, script: str, stderr: str, stdout: str, 
                              chain_id: int, attempt: int) -> Optional[str]:
        """Use LLM to fix Z3 script based on error messages"""
        try:
            # Build fixing prompt
            execution_error = f"Return code: non-zero\nSTDOUT: {stdout}\nSTDERR: {stderr}"
            
            prompt = self.prompt_manager.build_z3_fixer_prompt(
                original_script=script,
                execution_error=execution_error,
                stderr_output=stderr
            )
            
            system_role = self.prompt_manager.get_system_prompt("z3_fixer")
            
            # Call LLM using ask method
            response = self.llm_client.ask_with_logging(
                prompt=prompt,
                system_prompt=system_role,
                log_file_prefix=f"z3_fixer_attempt_{attempt}_chain_{chain_id}",
                stage="z3_constraint_solving",  # updated to the correct stage identifier
                chain_id=chain_id
            )
            
            # Extract fixed script from response
            fixed_script = self._extract_fixed_script(response)
            
            if fixed_script:
                self.logger.info(f"LLM provided a fixed Z3 script (attempt {attempt})")
                # Save the fixed script for debugging
                if self.debug:
                    import os
                    import time
                    
                    # Use unified debug session directory
                    session_dir = self._get_z3_debug_session_dir()
                    run_session_id = os.path.basename(session_dir)
                    fixes_dir = os.path.join(session_dir, "fixes")
                    
                    # Generate filename with timestamp for uniqueness
                    timestamp = int(time.time())
                    filename = f"chain_{chain_id}_fix_{attempt}_{timestamp}.py"
                    filepath = os.path.join(fixes_dir, filename)
                    
                    # Add header with session info
                    header = f"""# Z3 Fix Script for Chain {chain_id}
# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}
# Fix Attempt: {attempt}
# Run Session: {run_session_id}
# 
# This script was automatically generated by LLM for fixing Z3 errors.
#
"""
                    
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(header + fixed_script)
                    
                    # Set file permissions
                    os.chmod(filepath, 0o644)
                    
                    self.logger.info(f"Saved fixed Z3 script to: {filepath}")
                return fixed_script
            else:
                self.logger.warning(f"Could not extract fixed script from LLM response")
                return None
        
        except Exception as e:
            self.logger.error(f"Error fixing Z3 script with LLM: {e}")
            return None
    
    def _extract_fixed_script(self, llm_response: str) -> Optional[str]:
        """Extract the fixed Z3 script from LLM response"""
        # Try to extract Python code using BaseAgent's shared method
        script = self._extract_code_from_response(llm_response, "python")
        
        if script:
            # Validate that it looks like a Z3 script
            if ("from z3 import" in script or "import z3" in script) and "solver" in script:
                return script
        
        # Fallback: extract any code block and validate
        script = self._extract_code_from_response(llm_response)
        if script and ("from z3 import" in script or "import z3" in script) and "solver" in script:
            return script
        
        return None
    


    def _ensure_z3_debug_dirs(self) -> None:
        """Ensure Z3 debug directories exist under chain output dir"""
        import os
        
        # Create z3_debug directory under chain output dir
        debug_root = os.path.join(self.output_dir, "z3_debug")
        os.makedirs(debug_root, exist_ok=True)
    
    def _get_z3_debug_session_dir(self) -> str:
        """Get Z3 debug session directory and ensure it exists with subdirectories"""
        import os
        
        # Create session directory under z3_debug
        session_dir = os.path.join(self.output_dir, "z3_debug")
        os.makedirs(session_dir, exist_ok=True)
        
        # Create subdirectories for organized storage
        subdirs = ["scripts", "models", "fixes"]
        for subdir in subdirs:
            os.makedirs(os.path.join(session_dir, subdir), exist_ok=True)
        
        return session_dir
        
    
    def _save_z3_script(self, z3_script: str, chain_id: int, script_type: str = "script") -> str:
        """
        Save Z3 script to file for debugging purposes.
        
        Args:
            z3_script: The Z3 script content
            chain_id: Chain identifier
            script_type: Type of script (initial, final, fix_attempt_X)
            
        Returns:
            Path to saved script file
        """
        import os
        import time
        
        # Ensure z3_debug directory and subdirectories exist
        session_dir = self._get_z3_debug_session_dir()
        
        # Generate filename and save to scripts subdirectory
        timestamp = int(time.time())
        filename = f"z3_{script_type}_{timestamp}.py"
        filepath = os.path.join(session_dir, "scripts", filename)
        
        # Save script with simple header
        header = f"""# Z3 Script for Chain {chain_id}
# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}
# Type: {script_type}
# 
# This script was automatically generated for debugging purposes.
# You can run it directly with: python {filename}
#
"""
        
        full_content = header + z3_script
        
        # Write to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(full_content)
        
        # Set file permissions
        os.chmod(filepath, 0o644)
        
        return filepath
    
    def _save_z3_model_output(self, z3_output: str, chain_id: int) -> str:
        """
        Save Z3 model output (just the print result) when sat.
        
        Args:
            z3_output: Full stdout from Z3 execution
            chain_id: Chain identifier
            
        Returns:
            Path to saved model file
        """
        import os
        import time
        
        # Get unified debug session directory
        session_dir = self._get_z3_debug_session_dir()
        models_dir = os.path.join(session_dir, "models")
        
        # Generate filename
        timestamp = int(time.time())
        filename = f"chain_{chain_id}_model_{timestamp}.txt"
        filepath = os.path.join(models_dir, filename)
        
        # Save the output directly
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(z3_output)
        
        # Set file permissions
        os.chmod(filepath, 0o644)
        
        self.logger.info(f"Saved Z3 model output to: {filepath}")
        return filepath
    
    def _save_final_z3_script(self, z3_script: str, chain_id: int, status: str) -> str:
        """
        Save the final Z3 script with clear marking for easy identification.
        
        Args:
            z3_script: The final Z3 script content
            chain_id: Chain identifier  
            status: Result status (sat/unsat/unknown)
            
        Returns:
            Path to saved final script file
        """
        import os
        import time
        
        # Ensure z3_debug directory and subdirectories exist
        session_dir = self._get_z3_debug_session_dir()
        
        # Generate filename with FINAL prefix for easy identification
        timestamp = int(time.time())
        filename = f"FINAL_z3_chain_{chain_id}_{status}_{timestamp}.py"
        filepath = os.path.join(session_dir, "scripts", filename)
        
        # Save script with clear header marking it as final
        header = f"""# ========================================
# FINAL Z3 Script for Chain {chain_id}
# ========================================
# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}
# Status: {status.upper()} 
# Result: This is the FINAL successful Z3 script
# 
# This script represents the final working version after all fixes.
# You can run it directly with: python {filename}
#
"""
        
        full_content = header + z3_script
        
        # Write to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(full_content)
        
        # Set file permissions
        os.chmod(filepath, 0o644)
        
        return filepath

    def _build_z3_script_with_python_translator(self, region_analysis: Dict[str, Any]) -> str:
        """
        Build Z3 script using Python translator.
        
        The intermediate JSON format is actually necessary for structured constraint representation.
        """
        try:
            # Convert region analysis to structured constraints
            json_constraints = self._convert_region_analysis_to_json(region_analysis)
            
            # Validate constraints before proceeding
            if not json_constraints or not isinstance(json_constraints, dict):
                raise ValueError("Failed to extract valid constraints from region analysis")
            
            # Generate Z3 script using Python translator logic
            z3_script = self._generate_z3_from_json_constraints(json_constraints)
            
            # Validate generated script
            if not z3_script or not isinstance(z3_script, str):
                raise ValueError("Python translator failed to generate valid Z3 script")
            
            self.logger.info("Successfully generated Z3 script using Python translator")
            return z3_script
            
        except (ValueError, KeyError, AttributeError) as e:
            # Data format or processing errors - fail fast to expose the real issue
            self.logger.error(f"Python translator failed due to data issue: {e}")
            raise ValueError(f"Invalid region analysis data for Z3 generation: {e}") from e
            
        except Exception as e:
            # Unexpected errors - fail fast, don't hide the problem
            self.logger.error(f"Unexpected error in Z3 script generation: {e}")
            raise RuntimeError(f"Z3 script generation failed: {e}") from e
    
    def _convert_region_analysis_to_json(self, region_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert region analysis to JSON format expected by Python translator.

        The four-tuple ⟨Vars, Flow, Guard, Runtime⟩ from paper §3.5.1.
        Runtime predicates (e.g. serializable(C), reflection_accessible(C.f),
        module_opens(m,p), class_available(C), cast_compatible(src,dst)) are
        lowered to Z3 by templates/z3_translator_template.py:process_runtime_constraint.
        """
        json_data = {
            "vars": [],
            "flow": [],
            "guard": [],
            "runtime": []
        }
        
        gadgets = [g for r in region_analysis.get("regions", []) for g in r.get("gadgets", [])]
        if not gadgets:
            raise InconclusiveAnalysis("No gadgets were extracted from the chain")
        for gadget in gadgets:
            summary = gadget.get("code_summary") if isinstance(gadget, dict) else None
            if summary and summary.get("error"):
                raise RuntimeError(summary["error"])
            if not summary or summary.get("inconclusive"):
                raise InconclusiveAnalysis((summary or {}).get("inconclusive", "A gadget has no usable constraint summary"))
            self._extract_constraints_from_summary(summary, json_data)
        if not any(json_data.values()):
            raise InconclusiveAnalysis("No constraints were extracted from gadget summaries")
        self._add_inter_gadget_flows(region_analysis, json_data)
        return json_data

    def _extract_constraints_from_summary(self, code_summary, json_data):
        summary = code_summary.get("summary")
        constraints = self._extract_json_from_response(summary) if isinstance(summary, str) else None
        if not isinstance(constraints, dict):
            raise InconclusiveAnalysis("Constraint summary is not a JSON object")
        for key in ("vars", "flow", "guard", "runtime"):
            values = constraints.get(key)
            if not isinstance(values, list):
                raise InconclusiveAnalysis(f"Constraint summary requires a {key} list")
            for value in values:
                if not self._is_valid_constraint(value, key):
                    raise InconclusiveAnalysis(f"Unsupported {key} constraint: {value!r}")
            json_data[key].extend(values)

    def _extract_constraints_with_patterns(self, text: str) -> Optional[Dict[str, Any]]:
        """
        Fallback constraint extraction using pattern matching
        
        Args:
            text: Text that may contain constraint information
            
        Returns:
            Extracted constraints dict or None
        """
        import re
        
        try:
            result = {"vars": [], "flow": [], "guard": [], "runtime": []}

            # Pattern 1: Look for explicit constraint sections
            # vars: [{"name": "x", "constraint": "nonnull"}, ...]
            vars_pattern = r'(?:vars?|variables?)\s*[:\-]\s*\[(.*?)\]'
            vars_match = re.search(vars_pattern, text, re.DOTALL | re.IGNORECASE)
            if vars_match:
                vars_content = vars_match.group(1)
                result["vars"] = self._parse_vars_from_text(vars_content)

            # flow: ["x -> y", "y -> z", ...]
            flow_pattern = r'(?:flows?|flow_constraints?)\s*[:\-]\s*\[(.*?)\]'
            flow_match = re.search(flow_pattern, text, re.DOTALL | re.IGNORECASE)
            if flow_match:
                flow_content = flow_match.group(1)
                result["flow"] = self._parse_flow_from_text(flow_content)

            # guard: ["nonnull(x)", "type(y,String)", ...]
            guard_pattern = r'(?:guards?|guard_constraints?)\s*[:\-]\s*\[(.*?)\]'
            guard_match = re.search(guard_pattern, text, re.DOTALL | re.IGNORECASE)
            if guard_match:
                guard_content = guard_match.group(1)
                result["guard"] = self._parse_guard_from_text(guard_content)

            # runtime: ["serializable(C)", "reflection_accessible(C.f)", ...]
            runtime_pattern = r'(?:runtimes?|runtime_constraints?)\s*[:\-]\s*\[(.*?)\]'
            runtime_match = re.search(runtime_pattern, text, re.DOTALL | re.IGNORECASE)
            if runtime_match:
                runtime_content = runtime_match.group(1)
                result["runtime"] = self._parse_runtime_from_text(runtime_content)
            
            # Pattern 2: Look for inline constraint mentions
            # "x is nonnull", "x flows to y", "type of x is String"
            self._extract_inline_constraints(text, result)
            
            # Return result if we found any constraints
            if any(result.values()):
                self.logger.info(f"Extracted constraints using pattern matching: {result}")
                return result
            
        except Exception as e:
            self.logger.warning(f"Pattern-based constraint extraction failed: {e}")
        
        return None
    
    def _parse_vars_from_text(self, text: str) -> List[Dict[str, str]]:
        """Parse variable constraints from text"""
        import re
        result = []
        
        # Look for {"name": "x", "constraint": "nonnull"} patterns
        var_patterns = re.findall(r'\{\s*["\']?name["\']?\s*:\s*["\']([^"\']+)["\']?\s*,\s*["\']?constraint["\']?\s*:\s*["\']([^"\']+)["\']?\s*\}', text)
        for name, constraint in var_patterns:
            result.append({"name": name.strip(), "constraint": constraint.strip()})
        
        # Look for simple "name: constraint" patterns
        simple_patterns = re.findall(r'["\']?([a-zA-Z_]\w*)["\']?\s*:\s*["\']?(nonnull|StringSort|Obj|IntSort|BoolSort|==\w+)["\']?', text)
        for name, constraint in simple_patterns:
            if {"name": name, "constraint": constraint} not in result:
                result.append({"name": name.strip(), "constraint": constraint.strip()})
        
        return result
    
    def _parse_flow_from_text(self, text: str) -> List[str]:
        """Parse flow constraints from text"""
        import re
        result = []
        
        # Look for "x -> y" patterns
        flow_patterns = re.findall(r'["\']?([a-zA-Z_]\w*)\s*->\s*([a-zA-Z_]\w*)["\']?', text)
        for src, dst in flow_patterns:
            flow_str = f"{src.strip()} -> {dst.strip()}"
            if flow_str not in result:
                result.append(flow_str)
        
        return result
    
    def _parse_guard_from_text(self, text: str) -> List[str]:
        """Parse guard constraints from text"""
        import re
        result = []

        # Look for function-style constraints: nonnull(x), type(x,String), cmp(x=="value")
        guard_patterns = re.findall(r'((?:nonnull|type|cmp|range)\([^)]+\))', text, re.IGNORECASE)
        for guard in guard_patterns:
            if guard.strip() not in result:
                result.append(guard.strip())

        return result

    def _parse_runtime_from_text(self, text: str) -> List[str]:
        """Parse runtime feasibility predicates from text.

        Recognises the predicates listed in paper §3.5.1 (Figure 4 prompt):
          serializable(C), reflection_accessible(C.field),
          module_opens(module, package), class_available(C),
          cast_compatible(src, dst), not_anonymous_class(obj).
        """
        import re
        result = []
        runtime_patterns = re.findall(
            r'((?:serializable|reflection_accessible|module_opens|class_available|cast_compatible|not_anonymous_class)\([^)]+\))',
            text,
            re.IGNORECASE,
        )
        for predicate in runtime_patterns:
            normalised = predicate.strip()
            if normalised and normalised not in result:
                result.append(normalised)
        return result
    
    def _extract_inline_constraints(self, text: str, result: Dict[str, List]):
        """Extract constraints mentioned inline in natural language"""
        import re
        
        # "x is nonnull" -> guard: ["nonnull(x)"]
        nonnull_patterns = re.findall(r'([a-zA-Z_]\w*)\s+is\s+(?:not\s+null|nonnull)', text, re.IGNORECASE)
        for var in nonnull_patterns:
            guard = f"nonnull({var.strip()})"
            if guard not in result["guard"]:
                result["guard"].append(guard)
        
        # "x flows to y" -> flow: ["x -> y"]
        flow_patterns = re.findall(r'([a-zA-Z_]\w*)\s+flows?\s+to\s+([a-zA-Z_]\w*)', text, re.IGNORECASE)
        for src, dst in flow_patterns:
            flow = f"{src.strip()} -> {dst.strip()}"
            if flow not in result["flow"]:
                result["flow"].append(flow)
        
        # "type of x is String" -> guard: ["type(x,String)"]
        type_patterns = re.findall(r'type\s+of\s+([a-zA-Z_]\w*)\s+is\s+([a-zA-Z_]\w*)', text, re.IGNORECASE)
        for var, type_name in type_patterns:
            guard = f"type({var.strip()},{type_name.strip()})"
            if guard not in result["guard"]:
                result["guard"].append(guard)
    
    def _validate_constraints(self, constraints: List[Any], constraint_type: str) -> List[Any]:
        """
        Validate constraints before adding them to the final constraint set
        
        Args:
            constraints: List of constraints to validate
            constraint_type: Type of constraints (vars, flow, guard)
            
        Returns:
            List of valid constraints
        """
        valid_constraints = []
        
        for constraint in constraints:
            if self._is_valid_constraint(constraint, constraint_type):
                valid_constraints.append(constraint)
            else:
                self.logger.debug(f"Skipping invalid {constraint_type} constraint: {constraint}")
        
        return valid_constraints
    
    def _is_valid_constraint(self, constraint: Any, constraint_type: str) -> bool:
        """
        Check if a constraint is valid for the given type
        
        Args:
            constraint: Constraint to validate
            constraint_type: Type of constraint (vars, flow, guard)
            
        Returns:
            True if valid, False otherwise
        """
        import re
        
        try:
            if constraint_type == "vars":
                # Variable constraints should be dicts with name and constraint keys
                if isinstance(constraint, dict):
                    return "name" in constraint and "constraint" in constraint and \
                           isinstance(constraint["name"], str) and isinstance(constraint["constraint"], str)
                return False
            
            elif constraint_type == "flow":
                # Flow constraints should be strings with "->" pattern
                if isinstance(constraint, str):
                    return "->" in constraint and len(constraint.split("->")) == 2
                return False
            
            elif constraint_type == "guard":
                # Guard constraints should be strings with valid function patterns
                if isinstance(constraint, str):
                    # Check for known guard patterns
                    guard_patterns = [
                        r'^nonnull\([^)]+\)$',
                        r'^type\([^,]+,[^)]+\)$',
                        r'^cmp\([^=]+==[^)]+\)$',
                        r'^range\([^<]+<[^<]+<[^)]+\)$',
                        r'^(always_throw|early_return)$'
                    ]
                    return any(re.match(pattern, constraint.strip()) for pattern in guard_patterns)
                return False

            elif constraint_type == "runtime":
                # Runtime predicates from paper §3.5.1 / Figure 4 prompt
                if isinstance(constraint, str):
                    runtime_patterns = [
                        r'^serializable\([^)]+\)$',
                        r'^reflection_accessible\([^)]+\)$',
                        r'^module_opens\([^,]+,[^)]+\)$',
                        r'^class_available\([^)]+\)$',
                        r'^cast_compatible\([^,]+,[^)]+\)$',
                        r'^not_anonymous_class\([^)]+\)$',
                    ]
                    return any(re.match(p, constraint.strip()) for p in runtime_patterns)
                return False

        except Exception:
            return False

        return False
    
    def _add_inter_gadget_flows(self, region_analysis: Dict[str, Any], json_data: Dict[str, Any]):
        """Add flow constraints between gadgets based on the original chain"""
        try:
            original_chain = region_analysis.get("original_chain", [])
            if len(original_chain) < 2:
                return
            
            # Extract method signatures from the original chain
            method_sigs = []
            for gadget_str in original_chain:
                # Parse gadget string to extract method signatures
                # Format: "[TYPE] <method_sig> --> <target_method_sig>"
                if "-->" in gadget_str:
                    parts = gadget_str.split("-->")
                    if len(parts) >= 2:
                        # Extract source method (before -->)
                        source_part = parts[0].strip()
                        if ">" in source_part:
                            source_method = source_part.split(">")[0] + ">"
                            source_method = source_method.split("<")[-1]
                            method_sigs.append(source_method)
                        
                        # Extract target method (after -->)
                        target_part = parts[1].strip()
                        if "<" in target_part and ">" in target_part:
                            target_method = target_part.split("<")[1].split(">")[0]
                            if len(method_sigs) == 1:  # Only add the last target method
                                method_sigs.append(target_method)
            
            # Add flow constraints between consecutive methods
            for i in range(len(method_sigs) - 1):
                flow_constraint = f"{method_sigs[i]} -> {method_sigs[i+1]}"
                json_data["flow"].append(flow_constraint)
                self.logger.debug(f"Added inter-gadget flow: {flow_constraint}")
            
            # Add initial input flow
            if method_sigs:
                initial_flow = f"input -> {method_sigs[0]}"
                json_data["flow"].insert(0, initial_flow)
                self.logger.debug(f"Added initial flow: {initial_flow}")
                
        except Exception as e:
            self.logger.warning(f"Failed to add inter-gadget flows: {e}")
    
    def _extract_constraints_fallback(self, code_summary: Dict[str, Any], json_data: Dict[str, Any]):
        """Fallback constraint extraction when template fails"""
        summary = code_summary.get("summary", "").lower()
        
        # Simple fallback extraction
        if "null" in summary:
            var_name = f"var_{hash(summary) % 1000}"
            json_data["vars"].append({"name": var_name, "constraint": "nonnull"})
    
    def _generate_z3_from_json_constraints(self, json_constraints: Dict[str, Any]) -> str:
        """
        Generate Z3 script from JSON constraints using external template
        
        Args:
            json_constraints: Dict with "vars", "flow", "guard", "runtime" keys (paper §3.5.1 four-tuple)
            
        Returns:
            Complete Z3 script as string
        """
        try:
            # Load template functions
            import os
            import importlib.util
            
            # Get template file path
            current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            template_path = os.path.join(current_dir, "templates", "z3_translator_template.py")
            
            # Load template module
            spec = importlib.util.spec_from_file_location("z3_template", template_path)
            template_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(template_module)
            
            # Generate Z3 script using template
            z3_script = template_module.generate_z3_script_from_json(json_constraints)
            
            self.logger.info("Successfully generated Z3 script using external template")
            return z3_script
            
        except InconclusiveAnalysis:
            raise
        except (ImportError, ModuleNotFoundError) as e:
            # Template loading failed - this is a setup issue
            self.logger.error(f"Failed to load Z3 template module: {e}")
            raise RuntimeError(f"Z3 template system is not properly configured: {e}") from e
            
        except Exception as e:
            # Template execution failed - this is likely a data issue
            self.logger.error(f"Error generating Z3 script from template: {e}")
            raise ValueError(f"Failed to generate Z3 script from constraints: {e}") from e


    
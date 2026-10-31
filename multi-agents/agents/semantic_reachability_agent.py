"""
Semantic Reachability Agent
"""

import re
import hashlib
import json
from collections import OrderedDict

from typing import Dict, Any, List, Optional
from tools.analysis.outcomes import InconclusiveAnalysis
from .base_agent import BaseAgent
from tools.core import LLMClient
from tools.java_extraction import JavaCodeExtractor


class SemanticReachabilityAgent(BaseAgent):
    """
    Semantic Reachability Analysis Agent
    
    Core approach:
    1. Use unified prompt manager for better prompt handling
    2. Focus on essential semantic analysis
    3. Provide clear, structured output
    """
    
    def __init__(self, llm_client: LLMClient, project_root: str = None, debug: bool = False):
        super().__init__(llm_client, debug)
        # prompt_manager is now initialized in BaseAgent
        self.code_extractor = JavaCodeExtractor(project_root, debug)
        self.response_cache = OrderedDict()
        self.cache_size = 256
        self.cache_hits = 0

    def _ask_cached(self, prompt, system_prompt, validator, **kwargs):
        """Reuse only validated responses to identical requests within this scan."""
        key = hashlib.sha256(json.dumps({
            "provider": self.llm_client.provider, "model": self.llm_client.model,
            "defaults": self.llm_client.default_params, "prompt": prompt, "system": system_prompt,
            "parameters": {k: v for k, v in kwargs.items() if k not in {"chain_id", "log_file_prefix"}},
        }, sort_keys=True).encode()).hexdigest()
        if key in self.response_cache:
            self.cache_hits += 1
            self.response_cache.move_to_end(key)
            response, origin = self.response_cache[key]
            return response, {"cache_hit": True, "cache_source_chain": origin}
        response = self.llm_client.ask_with_logging(prompt, system_prompt=system_prompt, **kwargs)
        if self.cache_size > 0 and validator(response):
            self.response_cache[key] = (response, kwargs.get("chain_id"))
            while len(self.response_cache) > self.cache_size:
                self.response_cache.popitem(last=False)
        return response, {"cache_hit": False}

    def _valid_summary_response(self, response):
        parsed = self._extract_json_from_response(response) if isinstance(response, str) else None
        return isinstance(parsed, dict) and all(isinstance(parsed.get(k), list) for k in ("vars", "flow", "guard", "runtime"))

        
    def analyze_transitions(self, transitions: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """
        Analyze semantic reachability of region transitions
        
        Args:
            transitions: List of region transitions to analyze
            **kwargs: Additional parameters
            
        Returns:
            Analysis results with reachability information
        """
        self.logger.info(f"Starting semantic analysis for {len(transitions)} transitions")
        analyzed_transitions = []
        overall_reachable = True
        
        for i, transition in enumerate(transitions):
            try:
                analysis_result = self._analyze_single_transition(transition, i)
                analyzed_transitions.append(analysis_result)
                
                if not analysis_result.get("reachable", True):
                    overall_reachable = False
                    self.logger.info(f"Transition {i} is NOT reachable")
                else:
                    self.logger.info(f"Transition {i} is reachable")
                    
            except Exception as e:
                self.logger.error(f"Failed to analyze transition {i}: {e}")
                analyzed_transitions.append({
                    "transition_id": i,
                    "reachable": False,
                    "error": str(e),
                    "analysis_type": "error"
                })
                overall_reachable = False
        
        return {
            "analyzed_transitions": analyzed_transitions,
            "overall_reachable": overall_reachable,
            "total_transitions": len(transitions),
            "reachable_count": len([t for t in analyzed_transitions if t.get("reachable", False)])
        }
    
    def _analyze_single_transition(self, transition: Dict[str, Any], transition_id: int) -> Dict[str, Any]:
        """Analyze a single transition"""
        from_region = transition.get("from_region", {})
        to_region = transition.get("to_region", {})
        
        # Extract code from regions
        from_code = self._extract_region_code(from_region)
        to_code = self._extract_region_code(to_region)
        
        # Build context information
        method_context = self._build_method_context(transition)
        # call_info = self._build_call_info(transition) # no need since this info was constructed by us.
        
        # Generate prompt
        prompt = self.prompt_manager.build_reachability_prompt(
            from_code=from_code,
            to_code=to_code,
            method_context=method_context,
            # call_info=call_info
        )
        
        # Get system prompt
        system_prompt = self.prompt_manager.get_system_prompt("reachability_analyzer")
        
        # Call LLM with logging
        response = self.llm_client.ask_with_logging(
            prompt,
            system_prompt=system_prompt,
            log_file_prefix=f"semantic_transition_analysis_{transition_id}"
        )
        
        # Parse response
        analysis_result = self._parse_reachability_response(response)
        analysis_result["transition_id"] = transition_id
        analysis_result["analysis_type"] = "semantic_reachability"
        
        return analysis_result
    
    def _extract_region_code(self, region: Dict[str, Any]) -> str:
        """
        Extract source code from region - OPTIMIZED to reuse already extracted code
        
        This method prioritizes already extracted source code to avoid redundant extraction.
        """
        if not region:
            return "No code available"
        
        gadgets = region.get("gadgets", [])
        if not gadgets:
            return "No gadgets in region"
        
        # Use the first gadget as representative
        gadget = gadgets[0]
        
        # OPTIMIZED: Always prioritize pre-extracted source code
        return self._get_source_code_from_gadget(gadget, fallback_to_extraction=True)
    
    def _get_source_code_from_gadget(self, gadget_input, fallback_to_extraction: bool = False) -> str:
        """
        Unified method to get source code from gadget input
        
        Args:
            gadget_input: Gadget dict or string
            fallback_to_extraction: Whether to fallback to raw extraction if no pre-extracted code
            
        Returns:
            Source code string
        """
        # Priority 1: Use already extracted source code from region analysis
        if isinstance(gadget_input, dict) and gadget_input.get("source_code"):
            self.logger.info("✅ Using pre-extracted source_code from gadget dict")
            return gadget_input["source_code"]
        
        # Priority 2: Use source from source_extraction if available
        if isinstance(gadget_input, dict) and gadget_input.get("source_extraction", {}).get("source"):
            self.logger.info("✅ Using source from source_extraction field")
            return gadget_input["source_extraction"]["source"]
        
        # Priority 3: Get raw_gadget if gadget is dict
        if isinstance(gadget_input, dict):
            raw_gadget = gadget_input.get("raw_gadget")
            if not raw_gadget:
                return "Unavailable. Infer its deserialization role based on domain knowledge."
        else:
            # gadget_input is string
            raw_gadget = gadget_input
        
        # Priority 4: Fallback to extraction only if explicitly requested
        if fallback_to_extraction:
            self.logger.warning("⚠️ No pre-extracted source code found, falling back to extraction")
            source_code = self._extract_method_source_from_raw_gadget(raw_gadget)
            
            if source_code and not source_code.startswith("//"):  # Not an error message
                self.logger.info(f"✅ Successfully extracted source code ({len(source_code)} chars)")
                return source_code
            else:
                self.logger.warning(f"❌ Source extraction failed: {source_code[:100] if source_code else 'None'}...")
        
        return f"Unavailable. Infer its deserialization role based on domain knowledge."

    def _build_method_context(self, transition: Dict[str, Any]) -> str:
        """Build method context information"""
        from_region = transition.get("from_region", {})
        to_region = transition.get("to_region", {})
        
        context_parts = []
        
        if from_region:
            gadgets = from_region.get("gadgets", [])
            if gadgets:
                context_parts.append(f"The call edge is: {gadgets[0]}")
        
        return " -> ".join(context_parts) if context_parts else "Unknown method context"
    

    
    def _parse_reachability_response(self, response: str, context_info: str = "") -> Dict[str, Any]:
        """Parse LLM response for reachability analysis - simple REACHABLE|UNREACHABLE format"""
        if isinstance(response, str):
            # Accept a decision only, never keywords embedded in explanations.
            match = re.fullmatch(r"(REACHABLE|UNREACHABLE)(?:\s*\((.*)\))?", response.strip(), re.S)
            if match:
                return {
                    "reachable": match[1] == "REACHABLE",
                    "reasoning": match[2] or f"Method transition is {match[1].lower()}",
                }
        return {"reachable": None, "reasoning": "Missing or ambiguous reachability decision"}

    @staticmethod
    def _require_source(source_code):
        if not isinstance(source_code, str) or not source_code.strip() or source_code.startswith(
            ("Unavailable.", "Source code not available", "No code available", "// Failed", "// Error")
        ):
            raise InconclusiveAnalysis("Matching Java source is unavailable")

    def generate_gadget_code_summary(self, gadget_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate code summary for a SINGLE GADGET (not region)
        
        Args:
            gadget_info: Single gadget information including source code and metadata
            
        Returns:
            Code summary result for this gadget
        """
        gadget_id = gadget_info.get("gadget_id", "unknown")
        
        # Get source code for this specific gadget
        source_code = self._get_source_code_from_gadget(gadget_info, fallback_to_extraction=True)
        
        self._require_source(source_code)

        # Extract method signature
        if isinstance(gadget_info, dict):
            method_signature = gadget_info.get("method_signature", gadget_info.get("raw_gadget", "Unknown method"))
        else:
            method_signature = "Unknown method"
        
        # Extract method context from gadget info
        method_context = gadget_info.get("raw_gadget", "No call edge context available")
        
        # Build prompt using correct template parameters including METHOD_CONTEXT
        prompt = self.prompt_manager.build_prompt("code_summarizer",
            FULL_METHOD_SIGNATURE=method_signature,
            SOURCE_CODE=source_code,
            METHOD_CONTEXT=method_context
        )
        
        # Get system prompt
        system_prompt = self.prompt_manager.get_system_prompt("code_summarizer")
        
        # Call LLM with JSON format enforcement and logging - include chain_id for folder organization
        chain_id = gadget_info.get("chain_id")  # Extract chain_id from gadget_info
        raw_response, cache_info = self._ask_cached(
            prompt,
            system_prompt=system_prompt,
            validator=self._valid_summary_response,
            log_file_prefix=f"gadget_code_summary_{gadget_id}",
            stage="code_summary_and_constraints",  # updated to the correct stage identifier
            chain_id=chain_id,
            response_format='json'
        )
        
        # Extract summary from raw string response
        summary = self._extract_summary_from_response(raw_response)
        
        return {
            "gadget_id": gadget_id,
            "summary": summary,
            "method_signature": method_signature,
            "source_code": source_code,
            "analysis_type": "gadget_code_summary",
            **cache_info,
        }
    
    def generate_deserialization_audit(self, gadget_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate deserialization vulnerability audit for a SINGLE GADGET
        
        Args:
            gadget_info: Single gadget information including source code and metadata
            
        Returns:
            Deserialization audit result for this gadget
        """
        gadget_id = gadget_info.get("gadget_id", "unknown")
        
        # Get source code for this specific gadget
        source_code = self._get_source_code_from_gadget(gadget_info, fallback_to_extraction=True)
        
        # Extract method signature
        if isinstance(gadget_info, dict):
            method_signature = gadget_info.get("method_signature", gadget_info.get("raw_gadget", "Unknown method"))
        else:
            method_signature = "Unknown method"
        
        # Extract method context from gadget info
        method_context = gadget_info.get("raw_gadget", "No call edge context available")
        
        # Build prompt using deserialization auditor template
        prompt = self.prompt_manager.build_prompt("deserialization_auditor",
            FULL_METHOD_SIGNATURE=method_signature,
            SOURCE_CODE=source_code,
            METHOD_CONTEXT=method_context
        )
        
        # Get system prompt
        system_prompt = self.prompt_manager.get_system_prompt("deserialization_auditor")
        
        # Call LLM with logging - include chain_id for folder organization
        chain_id = gadget_info.get("chain_id")  # Extract chain_id from gadget_info
        response = self.llm_client.ask_with_logging(
            prompt,
            system_prompt=system_prompt,
            log_file_prefix=f"deserialization_audit_{gadget_id}",
            stage="deserialization_audit",
            chain_id=chain_id
        )
        
        # Extract audit result
        audit_result = self._extract_audit_from_response(response)
        
        return {
            "gadget_id": gadget_id,
            "audit_result": audit_result,
            "method_signature": method_signature,
            "source_code": source_code,
            "analysis_type": "deserialization_audit"
        }
    
    def _extract_audit_from_response(self, response: str) -> Dict[str, Any]:
        """
        Extract deserialization audit result from LLM response
        
        Args:
            response: LLM response containing JSON audit result
            
        Returns:
            Parsed audit result dictionary
        """
        try:
            # Clean up response
            response = response.strip()
            
            # Remove markdown code blocks if present
            response = response.replace("```json", "").replace("```", "")
            
            # Try to parse as JSON
            import json
            audit_result = json.loads(response)
            
            # Validate required fields
            required_fields = ["bypass_strategy", "exploitation_path", "security_concerns", "bypass_requirements"]
            for field in required_fields:
                if field not in audit_result:
                    audit_result[field] = f"Missing {field} information"
            
            return audit_result
            
        except json.JSONDecodeError as e:
            self.logger.warning(f"Failed to parse audit response as JSON: {e}")
            return {
                "bypass_strategy": "Failed to parse audit response",
                "exploitation_path": "Failed to parse audit response", 
                "security_concerns": "JSON parsing error",
                "bypass_requirements": "Unknown due to parsing error"
            }
        except Exception as e:
            self.logger.warning(f"Error extracting audit result: {e}")
            return {
                "bypass_strategy": "Error in audit analysis",
                "exploitation_path": "Error in audit analysis",
                "security_concerns": "Analysis error",
                "bypass_requirements": "Unknown due to analysis error"
            }
    
    def _extract_summary_from_response(self, response: str) -> str:
        """
        Extract summary from LLM response - updated for new prompt format
        
        New prompt expects simple text response focusing on flow and guard analysis
        """
        # Type safety check - Linus would approve of this paranoia
        if not isinstance(response, str):
            self.logger.error(f"Expected string response, got {type(response)}. This is a bug!")
            return "Error: invalid response type"
        
        # Clean up response
        response = response.strip()
        if not response:
            return "No summary extracted"

        # Remove markdown code blocks if present
        response = response.replace("```json", "").replace("```", "")
        
        return response.strip() if response.strip() else "No summary extracted"
    
    def analyze_region_edge_reachability(self, edge_info: Dict[str, Any], edge_index: int, chain_id: int = 0) -> Dict[str, Any]:
        """
        Analyze the reachability of a single region edge, for early stop decision.
        
        Args:
            edge_info: Region edge information including raw call edge and source code
            edge_index: Index of the edge being analyzed
            chain_id: Chain identifier for log organization
            
        Returns:
            Reachability analysis result with early_stop flag
        """
        try:
            self.logger.info(f"Analyzing reachability for region edge {edge_index}")
            call_edge = edge_info.get('raw_call_edge', {}).get('raw_gadget', 'Unknown call edge')
            
            source_method_code = edge_info.get('source_method_code', 'Source code not available')
            
            self._require_source(source_method_code)

            # construct method context, from raw call edge
            method_context = f"{call_edge}"
            
            # use existing reachability_analyzer template
            prompt = self.prompt_manager.build_reachability_prompt(
                from_code=source_method_code,
                # to_code="Target method call based on edge analysis",
                method_context=method_context,
                # call_info=call_info
            )
            
            # get system prompt
            system_prompt = self.prompt_manager.get_system_prompt("reachability_analyzer")
            
            # call LLM
            response, cache_info = self._ask_cached(
                prompt,
                system_prompt=system_prompt,
                validator=lambda response: self._parse_reachability_response(response)["reachable"] is not None,
                log_file_prefix=f"region_edge_reachability_{edge_index}",
                stage="semantic_reachability",  # updated to the correct stage identifier
                chain_id=chain_id
            )
            
            # parse response - using unified parsing logic and adding early_stop decision
            analysis_result = self._parse_reachability_response(response, f"region edge {edge_index}")
            
            # add early_stop decision
            analysis_result.update(cache_info)
            analysis_result["early_stop"] = analysis_result.get("reachable") is False
            
            self.logger.info(f"Region edge {edge_index} reachability: {analysis_result.get('reachable', False)}")
            
            return analysis_result
            
        except InconclusiveAnalysis as e:
            return {"reachable": None, "early_stop": False, "reasoning": str(e)}
        except Exception as e:
            self.logger.error(f"Error analyzing region edge {edge_index} reachability: {e}")
            return {
                "reachable": None,
                "reasoning": f"Error in reachability analysis: {e}",
                "early_stop": False,
                "error": str(e)
            }

    
    
    def _extract_method_source_from_raw_gadget(self, raw_gadget: str) -> str:
        """
        Extract method source code from raw gadget string
        
        Args:
            raw_gadget: Raw gadget string
            
        Returns:
            Method source code or error message
        """
        try:
            from tools.java_extraction.signature_parser import extract_source_signature
            
            # parse gadget to get method signature
            class_name, method_signature, line_number = extract_source_signature(raw_gadget)
            
            if not method_signature:
                return f"// Failed to parse method signature from: {raw_gadget[:100]}..."
            
            # extract source code
            source_code = self.code_extractor.extract_method_source(method_signature, line_number)
            
            if source_code:
                return source_code
            else:
                return "Unavailable. Infer its deserialization role based on domain knowledge."
                
        except Exception as e:
            return "Unavailable. Infer its deserialization role based on domain knowledge." 
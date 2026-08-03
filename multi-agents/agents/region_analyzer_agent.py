"""
Region Analyzer Agent
Optimized version using unified code analyzer
"""

import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

from tools.java_extraction import JavaCodeExtractor
from .base_agent import BaseAgent


class RegionType(Enum):
    """Types of regions"""
    STATIC_ANALYZABLE = "static_analyzable"
    LLM_REQUIRED = "llm_required"


@dataclass
class RegionInfo:
    """Information about a region in the gadget chain"""
    region_id: int
    start_gadget: int
    end_gadget: int
    gadgets: List[str]
    region_type: RegionType
    constraints: List[Dict[str, Any]]
    exit_conditions: List[str] = field(default_factory=list)
    entry_conditions: List[str] = field(default_factory=list)
    receiver: Optional[str] = None
    invoke_type: Optional[str] = None
    
    def __post_init__(self):
        if self.constraints is None:
            self.constraints = []
        if self.exit_conditions is None:
            self.exit_conditions = []
        if self.entry_conditions is None:
            self.entry_conditions = []


class RegionAnalyzerAgent(BaseAgent):
    """
    Region Analyzer Agent using unified code analyzer
    """
    
    def __init__(self, llm_client, project_root: str = None, debug: bool = False):
        super().__init__(llm_client, debug)
        self.code_extractor = JavaCodeExtractor(project_root, debug)

        # prompt_manager is now initialized in BaseAgent
        
    def analyze_gadget_chain(self, chain: List[str], chain_id: int) -> Dict[str, Any]:
        """
        Analyze a gadget chain and extract regions with constraints
        
        Args:
            chain: List of gadget strings
            chain_id: Chain identifier
            
        Returns:
            Analysis result with regions and constraints
        """
        self.logger.info(f"Analyzing chain {chain_id} with {len(chain)} gadgets")
        
        # Parse gadget chain
        parsed_gadgets = self._parse_gadget_chain(chain)
        
        # Identify regions
        regions = self._identify_regions(parsed_gadgets)

        # Extract constraints for each region
        for region in regions:
            self._extract_region_constraints(region)
        
        # Analyze region transitions
        transitions = self._analyze_region_transitions(regions, parsed_gadgets)
        
        return {
            "chain_id": chain_id,
            "original_chain": chain,
            "parsed_gadgets": parsed_gadgets,
            "regions": [self._region_to_dict(r, parsed_gadgets) for r in regions],
            "transitions": transitions,
            "analysis_metadata": {
                "total_regions": len(regions),
                "static_regions": len([r for r in regions if r.region_type == RegionType.STATIC_ANALYZABLE]),
                "llm_regions": len([r for r in regions if r.region_type == RegionType.LLM_REQUIRED]),
                "total_transitions": len(transitions)
            }
        }
    
    def _parse_gadget_chain(self, chain: List[str]) -> List[Dict[str, Any]]:
        """Parse gadget chain into structured format"""
        parsed_gadgets = []
        
        for i, gadget in enumerate(chain):
            parsed = self._parse_single_gadget(gadget, i)
            if parsed:
                parsed_gadgets.append(parsed)
        
        return parsed_gadgets
    
    def _parse_single_gadget(self, gadget: str, gadget_id: int) -> Optional[Dict[str, Any]]:
        """Parse a single gadget string"""
        # Import the signature parser
        from tools.java_extraction.signature_parser import extract_source_signature
        
        # Extract class name and method signature from Flash format
        class_name, full_signature, line_number = extract_source_signature(gadget)
        
        if not full_signature:
            self.logger.warning(f"Invalid gadget format: {gadget}")
            return None
        
        # Extract source code using CodeExtractor
        source_code = self.code_extractor.extract_method_source(full_signature, line_number)
        
        # Extract method name from full signature for display
        method_name = "N/A"
        if full_signature:
            import re
            method_match = re.search(r':\s*([^(]+)', full_signature)
            if method_match:
                method_name = method_match.group(1).strip()
        
        return {
            "gadget_id": gadget_id,
            "raw_gadget": gadget,  # Changed from 'gadget' to 'raw_gadget' for test compatibility
            "class_name": class_name,
            "method_signature": full_signature,
            "method_name": method_name,  # Added for test compatibility
            "source_code": source_code,
            "has_source": bool(source_code),
            "source_extraction": {  # Added for test compatibility
                "success": bool(source_code),
                "source": source_code if source_code else "",
                "line_number": line_number
            }
        }
    
    def _identify_regions(self, gadgets: List[Dict[str, Any]]) -> List[RegionInfo]:
        """Identify regions in the gadget chain"""
        regions = []
        current_region = None
        
        for i, gadget in enumerate(gadgets):
            region_type = self._determine_region_type(gadget)
            
            # if `llm_required`, always create a new region 
            if region_type == RegionType.LLM_REQUIRED:
                # save the previous region
                if current_region:
                    regions.append(current_region)
                
                # create a new llm_required region (only contains one gadget)
                current_region = RegionInfo(
                    region_id=len(regions),
                    start_gadget=i,
                    end_gadget=i,
                    gadgets=[gadget["raw_gadget"]],
                    region_type=region_type,
                    constraints=[]
                )
            else:
                # static_analyzable 
                if not current_region or current_region.region_type != RegionType.STATIC_ANALYZABLE:
                    # save the previous region
                    if current_region:
                        regions.append(current_region)
                    
                    # create a new static_analyzable region
                    current_region = RegionInfo(
                        region_id=len(regions),
                        start_gadget=i,
                        end_gadget=i,
                        gadgets=[gadget["raw_gadget"]],
                        region_type=region_type,
                        constraints=[]
                    )
                else:
                    # continue the current static_analyzable region
                    current_region.gadgets.append(gadget["raw_gadget"])
                    current_region.end_gadget = i
        
        # add the last region
        if current_region:
            regions.append(current_region)
        
        if self.debug:
            self.logger.info(f"Split chain into {len(regions)} regions:")
            for region in regions:
                self.logger.info(f"  Region {region.region_id}: {region.region_type.value} [{region.start_gadget}-{region.end_gadget}] ({len(region.gadgets)} gadgets)")
        
        return regions
    
    def _determine_region_type(self, gadget: Dict[str, Any]) -> RegionType:
        """Determine if gadget requires LLM analysis (consistent with standalone logic)"""
        from tools.analysis.code_analysis import extract_invoke_type
        
        # Extract raw gadget string for invoke type analysis
        raw_gadget = gadget.get("raw_gadget", "")
        if not raw_gadget:
            return RegionType.STATIC_ANALYZABLE  # Default
        
        # Use the same logic as standalone determine_region_type function
        invoke_type = extract_invoke_type(raw_gadget)
        if not invoke_type:
            return RegionType.STATIC_ANALYZABLE  # Default
        
        # determine the region type based on the invoke type
        if invoke_type in ["INVOKESTATIC", "INVOKESPECIAL"]:
            return RegionType.STATIC_ANALYZABLE
        elif invoke_type in ["INVOKEVIRTUAL", "INVOKEINTERFACE", "INVOKEDYNAMIC"]:
            return RegionType.LLM_REQUIRED
        else:
            return RegionType.STATIC_ANALYZABLE  # Default
    
    def _extract_region_constraints(self, region: RegionInfo):
        """
        Extract basic structural constraints for a region
        
        OPTIMIZED: This method focuses on basic structural constraints only.
        For detailed semantic analysis, use SemanticReachabilityAgent.generate_gadget_code_summary()
        """
        constraints = []
        
        # Basic region-level constraints
        if region.region_type.value == "llm_required":
            # LLM regions typically have dynamic dispatch constraints
            constraint_dict = {
                "type": "dynamic_dispatch",
                "description": f"Region {region.region_id} requires dynamic dispatch analysis",
                "z3_formula": f"dynamic_dispatch_region_{region.region_id} == True",
                "severity": "high",
                "metadata": {
                    "region_type": region.region_type.value,
                    "gadget_count": len(region.gadgets)
                }
            }
            constraints.append(constraint_dict)
        else:
            # Static regions have more predictable constraints
            constraint_dict = {
                "type": "static_dispatch",
                "description": f"Region {region.region_id} has static dispatch patterns",
                "z3_formula": f"static_dispatch_region_{region.region_id} == True",
                "severity": "low",
                "metadata": {
                    "region_type": region.region_type.value,
                    "gadget_count": len(region.gadgets)
                }
            }
            constraints.append(constraint_dict)
        
        # Add transition constraints based on region position
        if region.region_id > 0:  # Not the first region
            constraint_dict = {
                "type": "region_transition",
                "description": f"Region {region.region_id} requires valid transition from previous region",
                "z3_formula": f"region_transition_{region.region_id - 1}_to_{region.region_id} == True",
                "severity": "medium",
                "metadata": {
                    "source_region": region.region_id - 1,
                    "target_region": region.region_id
                }
            }
            constraints.append(constraint_dict)
        
        region.constraints = constraints
    
    def _analyze_region_transitions(self, regions: List[RegionInfo], parsed_gadgets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze transitions between regions"""
        transitions = []
        
        for i in range(len(regions) - 1):
            from_region = regions[i]
            to_region = regions[i + 1]
            
            transition = {
                "transition_id": i,
                "from_region": self._region_to_dict(from_region, parsed_gadgets),
                "to_region": self._region_to_dict(to_region, parsed_gadgets),
                "transition_type": self._determine_transition_type(from_region, to_region),
                "constraints": self._extract_transition_constraints(from_region, to_region)
            }
            
            transitions.append(transition)
        
        return transitions
    
    def _determine_transition_type(self, from_region: RegionInfo, to_region: RegionInfo) -> str:
        """Determine the type of transition between regions"""
        if from_region.region_type == RegionType.STATIC_ANALYZABLE and to_region.region_type == RegionType.STATIC_ANALYZABLE:
            return "static_to_static"
        elif from_region.region_type == RegionType.STATIC_ANALYZABLE and to_region.region_type == RegionType.LLM_REQUIRED:
            return "static_to_llm"
        elif from_region.region_type == RegionType.LLM_REQUIRED and to_region.region_type == RegionType.STATIC_ANALYZABLE:
            return "llm_to_static"
        else:
            return "llm_to_llm"
    
    def _extract_transition_constraints(self, from_region: RegionInfo, to_region: RegionInfo) -> List[str]:
        """Extract constraints for region transition"""
        constraints = []
        
        # Add exit conditions from from_region
        constraints.extend(from_region.exit_conditions)
        
        # Add entry conditions for to_region
        constraints.extend(to_region.entry_conditions)
        
        return constraints
    
    def _region_to_dict(self, region: RegionInfo, parsed_gadgets: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Convert region to dictionary with parsed gadget data"""
        # Use parsed gadgets if available, otherwise fall back to raw gadgets
        if parsed_gadgets:
            region_gadgets = []
            for i in range(region.start_gadget, region.end_gadget + 1):
                if i < len(parsed_gadgets):
                    region_gadgets.append(parsed_gadgets[i])
                else:
                    # Fallback for edge cases
                    region_gadgets.append({"raw_gadget": region.gadgets[i - region.start_gadget] if i - region.start_gadget < len(region.gadgets) else "Unknown"})
        else:
            # Fallback to original behavior
            region_gadgets = region.gadgets
        
        return {
            "region_id": region.region_id,
            "start_gadget": region.start_gadget,
            "end_gadget": region.end_gadget,
            "gadgets": region_gadgets,
            "region_type": region.region_type.value,
            "constraints": region.constraints,
            "exit_conditions": region.exit_conditions,
            "entry_conditions": region.entry_conditions,
            "receiver": region.receiver,
            "invoke_type": region.invoke_type
        }
    
    def batch_analyze_chains(self, chains: List[List[str]], max_chains: int = 10) -> List[Dict[str, Any]]:
        """Analyze multiple chains in batch"""
        results = []
        
        for i, chain in enumerate(chains[:max_chains]):
            try:
                result = self.analyze_gadget_chain(chain, i)
                results.append(result)
                self.logger.info(f"Completed analysis for chain {i}")
            except Exception as e:
                self.logger.error(f"Failed to analyze chain {i}: {e}")
                results.append({
                    "chain_id": i,
                    "original_chain": chain,
                    "error": str(e)
                })
        
        return results
    
    def analyze_chain_with_detailed_constraints(self, chain: List[str], chain_id: int, 
                                              semantic_agent=None) -> Dict[str, Any]:
        """
        ENHANCED: Analyze gadget chain with optional detailed constraint analysis
        
        Args:
            chain: List of gadget strings
            chain_id: Chain identifier
            semantic_agent: Optional SemanticReachabilityAgent for detailed constraint analysis
            
        Returns:
            Analysis result with optional detailed constraints
        """
        self.logger.info(f"Starting enhanced analysis for chain {chain_id} with detailed constraints")
        
        # Step 1: Basic region analysis
        basic_result = self.analyze_gadget_chain(chain, chain_id)
        
        # Step 2: Optional detailed constraint analysis
        if semantic_agent:
            self.logger.info("Performing detailed constraint analysis using SemanticReachabilityAgent")
            
            detailed_constraints = {}
            regions = basic_result.get("regions", [])
            
            for region in regions:
                region_id = region.get("region_id", -1)
                
                # Process each gadget in the region individually
                gadgets = region.get("gadgets", [])
                self.logger.info(f"Processing {len(gadgets)} gadgets in region {region_id}")
                
                for gadget_idx, gadget in enumerate(gadgets):
                    if isinstance(gadget, dict):
                        gadget_id = f"r{region_id}_g{gadget_idx}"
                        
                        gadget_info = {
                            "gadget_id": gadget_id,
                            "raw_gadget": gadget.get("raw_gadget", ""),
                            "method_signature": gadget.get("method_signature", ""),
                            "region_type": region.get("region_type", "unknown"),
                            "source_code": gadget.get("source_code"),
                            "source_extraction": gadget.get("source_extraction", {})
                        }
                        
                        try:
                            # Generate code summary for this gadget (includes constraint extraction)
                            code_summary = semantic_agent.generate_gadget_code_summary(gadget_info)
                            
                            # NOTE: Constraint extraction is integrated into the code summary; no separate call needed
                            detailed_constraints[gadget_id] = {
                                "code_summary": code_summary
                            }
                            
                            self.logger.info(f"✅ Analyzed gadget {gadget_id}")
                            
                        except Exception as e:
                            self.logger.warning(f"❌ Failed to analyze gadget {gadget_id}: {e}")
                            detailed_constraints[gadget_id] = {"error": str(e)}
            
            # Add detailed constraints to result
            basic_result["detailed_constraints"] = detailed_constraints
            basic_result["analysis_metadata"]["has_detailed_constraints"] = True
            basic_result["analysis_metadata"]["detailed_constraint_regions"] = len(detailed_constraints)
        
        return basic_result 
"""
Region Analysis Utilities
Functions for splitting gadget chains into regions based on analysis requirements

Original functions from: StaticAnalysisAgent (agents/static_analysis_agent.py)
"""

from typing import List, Dict, Any
from .code_analysis import extract_invoke_type


def split_regions(chain: List[str], chain_index: int = 0) -> List[Dict[str, Any]]:
    """
    Split the specified chain into regions
    
    The core idea of the algorithm
    - Continuous static_analyzable calls can be merged into a region
    - Each llm_required call is an independent region, cannot be merged
    
    Original function: StaticAnalysisAgent.split_regions
    
    Args:
        chain: List of gadget strings to split
        chain_index: Chain index for logging purposes
        
    Returns:
        List[Dict]: region list, each region contains:
        {
            "region_id": int,
            "region_type": str,  # "static_analyzable", "llm_required"
            "gadgets": List[str],  # The gadgets in the region
            "start_index": int,   # The start index in the original chain
            "end_index": int      # The end index in the original chain
        }
    """
    if not chain:
        print(f"[RegionAnalysis] No chain at index {chain_index}, cannot split regions")
        return []
    
    regions = []
    current_region = None
    
    for i, gadget in enumerate(chain):
        region_type = determine_region_type(gadget)
        
        # If it is llm_required, always create a new region
        if region_type == "llm_required":
            # Save the previous region
            if current_region:
                current_region["end_index"] = i - 1
                regions.append(current_region)
            
            # Create a new llm_required region (only contains one gadget)
            current_region = {
                "region_id": len(regions),
                "region_type": region_type,
                "gadgets": [gadget],
                "start_index": i,
                "end_index": i
            }
        else:
            # static_analyzable case
            if not current_region or current_region["region_type"] != "static_analyzable":
                # Save the previous region
                if current_region:
                    current_region["end_index"] = i - 1
                    regions.append(current_region)
                
                # Create a new static_analyzable region
                current_region = {
                    "region_id": len(regions),
                    "region_type": region_type,
                    "gadgets": [gadget],
                    "start_index": i,
                    "end_index": i
                }
            else:
                # Continue the current static_analyzable region
                current_region["gadgets"].append(gadget)
                current_region["end_index"] = i
    
    # Add the last region
    if current_region:
        regions.append(current_region)
    
    print(f"[RegionAnalysis] Split chain {chain_index} ({len(chain)} gadgets) into {len(regions)} regions")
    return regions


def determine_region_type(gadget: str) -> str:
    """
    Determine the region type based on the gadget invoke type
    
    Classification standard:
    - "static_analyzable": The call that can be fully parsed by static analysis tool
    - "llm_required": The call that requires LLM for semantic confirmation
    
    Original function: StaticAnalysisAgent._determine_region_type
    
    Args:
        gadget: gadget method signature, format: [INVOKETYPE] <class:method> --(line:xxx, constraint:xxx)--> <next_class:next_method>
        
    Returns:
        str: region type ("static_analyzable", "llm_required")
    """
    # Extract invoke type
    invoke_type = extract_invoke_type(gadget)
    if not invoke_type:
        return "static_analyzable"  # Default type
    
    # Determine the region type based on the invoke type
    if invoke_type in ["INVOKESTATIC", "INVOKESPECIAL"]:
        return "static_analyzable"
    elif invoke_type in ["INVOKEVIRTUAL", "INVOKEINTERFACE", "INVOKEDYNAMIC"]:
        return "llm_required"
    else:
        return "static_analyzable"  # Default type 
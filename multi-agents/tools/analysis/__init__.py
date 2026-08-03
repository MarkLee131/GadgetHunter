"""
Code Analysis Module

Tools for analyzing Java code, chains, and generating Z3 constraints.
"""

from .code_analysis import (
    analyze_security_checks, extract_exceptions, extract_method_calls,
    # detect_potential_vulnerabilities, calculate_method_complexity,
    extract_invoke_type, extract_method_signature
)
from .chain_parser import (
    parse_chains_file, parse_chains_flash_format, find_chains_file, 
    get_chains_file, load_chains_file
)
from .region_analysis import split_regions, determine_region_type
from .z3_manager import Z3ScriptManager

__all__ = [
    'analyze_security_checks',
    'extract_exceptions', 
    'extract_method_calls',
    # 'detect_potential_vulnerabilities',
    # 'calculate_method_complexity',
    'extract_invoke_type',
    'extract_method_signature',
    'parse_chains_file',
    'parse_chains_flash_format',
    'find_chains_file',
    'get_chains_file',
    'load_chains_file',
    'split_regions',
    'determine_region_type',
    'Z3ScriptManager'
]
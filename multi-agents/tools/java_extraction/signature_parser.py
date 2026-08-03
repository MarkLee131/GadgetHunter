"""
Signature Parser
Utilities for parsing method signatures and gadget chain edges

Original functions from: chain_utils.py
"""

import re
from typing import List, Tuple, Optional


def extract_source_signature(edge: str) -> Tuple[str, Optional[str], int]:
    """
    Extract class_name, full_sig, line_number from the edge string of the gadget chain
    
    Original function: extract_source_signature from chain_utils.py
    
    Args:
        edge: Gadget chain edge string, e.g.:
              '[VIRTUAL] <javax.swing.text.html.CSS: void readObject(java.io.ObjectInputStream)> --(line:3368, constraint:[-3, 0, 0])--> <java.util.Hashtable: java.lang.Object put(java.lang.Object,java.lang.Object)>'
    
    Returns:
        Tuple of (class_name, full_signature, line_number)
        - class_name: The class name (e.g., 'javax.swing.text.html.CSS')
        - full_signature: Full method signature (e.g., '<javax.swing.text.html.CSS: void readObject(java.io.ObjectInputStream)>')
        - line_number: Line number from the edge (-1 if not found)
    """
    m = re.search(r'<([\w.$]+):\s*([^>]+)>', edge)
    line_m = re.search(r'line:(-?\d+)', edge)
    line_number = int(line_m.group(1)) if line_m else -1
    
    if m:
        class_name = m.group(1)
        method_sig = m.group(2)
        full_sig = f"<{class_name}: {method_sig}>"
        return class_name, full_sig, line_number
    
    return "unknown", None, -1


def parse_method_signature(signature: str) -> Tuple[Optional[str], str, str, List[str]]:
    """
    Parse a method signature into its components
    
    Extended from parsing logic in code_extractor.py
    
    Args:
        signature: Method signature string
        
    Returns:
        Tuple of (class_name, return_type, method_name, param_types)
    """
    # Full signature format: <class: returnType methodName(paramType1,...)>
    m = re.match(r'<(.+?):\s+(\S+)\s+(\w+)\((.*)\)>', signature)
    if m:
        class_name, return_type, method_name, param_str = m.groups()
        param_types = [p.strip() for p in param_str.split(',')] if param_str.strip() else []
        return class_name, return_type, method_name, param_types
    
    # Simple signature format: returnType methodName(paramType1,...)
    m2 = re.match(r'(\S+)\s+(\w+)\((.*)\)', signature)
    if m2:
        return_type, method_name, param_str = m2.groups()
        param_types = [p.strip() for p in param_str.split(',')] if param_str.strip() else []
        return None, return_type, method_name, param_types
    
    raise ValueError(f"Invalid signature format: {signature}")


def normalize_type_name(type_str: str) -> str:
    """
    Normalize Java type name by removing generics and array brackets
    
    Extended from normalization logic in code_extractor.py
    
    Args:
        type_str: Java type string
        
    Returns:
        Normalized type string
    """
    if not type_str:
        return ''
    
    # Remove modifiers
    type_str = type_str.replace('final ', '').replace('volatile ', '').replace('transient ', '')
    
    # Remove generics
    type_str = re.sub(r'<.*?>', '', type_str)
    
    # Remove array brackets
    type_str = type_str.replace('[]', '').strip()
    
    return type_str


def get_short_type_name(type_str: str) -> str:
    """
    Get short type name (simple class name without package)
    
    Extended from short type logic in code_extractor.py
    
    Args:
        type_str: Full type name
        
    Returns:
        Simple class name
    """
    if not type_str:
        return ''
    
    # Normalize first
    type_str = normalize_type_name(type_str)
    
    # Get simple name
    return type_str.split('.')[-1]


def create_short_signature(method_name: str, param_types: List[str], return_type: str) -> Tuple[str, List[str], str]:
    """
    Create short signature with simple type names
    
    Extended from short signature logic in code_extractor.py
    
    Args:
        method_name: Method name
        param_types: List of parameter types
        return_type: Return type
        
    Returns:
        Tuple of (method_name, short_param_types, short_return_type)
    """
    short_params = [get_short_type_name(p) for p in param_types]
    short_ret = get_short_type_name(return_type)
    return method_name, short_params, short_ret
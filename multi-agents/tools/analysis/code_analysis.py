"""
Code Analysis Utilities
Helper functions for Java code analysis
"""

import re
from typing import List, Dict, Any


def analyze_security_checks(body: str) -> List[str]:
    """
    Analyze method body for security-related checks
    
    Original function: JavaCodeExtractor._analyze_security_checks from code_extractor.py
    
    Args:
        body: Method body source code
        
    Returns:
        List of security check descriptions found in the code
    """
    checks = []
    
    # Common security patterns
    security_patterns = [
        (r'checkPermission\s*\(', 'Permission check'),
        (r'isAccessible\s*\(', 'Accessibility check'),
        (r'validate\s*\(', 'Validation check'),
        (r'assert\s+', 'Assertion'),
        (r'if\s*\([^)]*null[^)]*\)', 'Null check'),
        (r'instanceof\s+', 'Type check'),
        (r'getSecurityManager\s*\(', 'Security manager check'),
    ]
    
    for pattern, description in security_patterns:
        if re.search(pattern, body, re.IGNORECASE):
            checks.append(description)
    
    return checks


def extract_exceptions(body: str) -> List[str]:
    """
    Extract exceptions that might be thrown from method body
    
    Original function: JavaCodeExtractor._extract_exceptions from code_extractor.py
    
    Args:
        body: Method body source code
        
    Returns:
        List of exception class names that might be thrown
    """
    exceptions = []
    
    # Look for throw statements
    throw_pattern = r'throw\s+new\s+(\w+(?:\.\w+)*)'
    for match in re.finditer(throw_pattern, body):
        exceptions.append(match.group(1))
    
    return list(set(exceptions))


def extract_method_calls(body: str) -> List[str]:
    """
    Extract method calls from the method body
    
    Original function: JavaCodeExtractor._extract_method_calls from code_extractor.py
    
    Args:
        body: Method body source code
        
    Returns:
        List of method calls in format "object.method"
    """
    calls = []
    
    # Simple method call pattern
    call_pattern = r'(\w+)\s*\.\s*(\w+)\s*\('
    for match in re.finditer(call_pattern, body):
        calls.append(f"{match.group(1)}.{match.group(2)}")
    
    return list(set(calls))


def extract_field_accesses(body: str) -> List[str]:
    """
    Extract field access patterns from method body
    
    Extended functionality based on code_extractor.py patterns
    
    Args:
        body: Method body source code
        
    Returns:
        List of field accesses in format "object.field"
    """
    accesses = []
    
    # Field access pattern (not followed by parentheses)
    field_pattern = r'(\w+)\s*\.\s*(\w+)(?!\s*\()'
    for match in re.finditer(field_pattern, body):
        accesses.append(f"{match.group(1)}.{match.group(2)}")
    
    return list(set(accesses))


def extract_control_flow_statements(body: str) -> Dict[str, int]:
    """
    Count control flow statements in method body
    
    Extended functionality based on code_extractor.py patterns
    
    Args:
        body: Method body source code
        
    Returns:
        Dictionary with counts of different control flow statements
    """
    control_flow = {
        'if_statements': 0,
        'for_loops': 0,
        'while_loops': 0,
        'try_catch_blocks': 0,
        'switch_statements': 0,
        'return_statements': 0
    }
    
    patterns = {
        'if_statements': r'\bif\s*\(',
        'for_loops': r'\bfor\s*\(',
        'while_loops': r'\bwhile\s*\(',
        'try_catch_blocks': r'\btry\s*\{',
        'switch_statements': r'\bswitch\s*\(',
        'return_statements': r'\breturn\b'
    }
    
    for statement_type, pattern in patterns.items():
        control_flow[statement_type] = len(re.findall(pattern, body))
    
    return control_flow


def get_class_info(class_name: str, class_file: str) -> Dict[str, Any]:
    """
    Get basic class information from source file
    
    Original function: JavaCodeExtractor._get_class_info from code_extractor.py
    
    Args:
        class_name: Full class name
        class_file: Path to class file
        
    Returns:
        Dictionary with class information
    """
    if not class_file:
        return {}
    
    try:
        with open(class_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Extract class modifiers, inheritance, etc.
        class_name_simple = class_name.split(".")[-1]
        class_pattern = r'class\s+{}\s*(?:extends\s+(\w+))?\s*(?:implements\s+([^{{]+))?\s*{{'.format(class_name_simple)
        match = re.search(class_pattern, content)
        
        if match:
            return {
                "extends": match.group(1),
                "implements": [i.strip() for i in match.group(2).split(',')] if match.group(2) else [],
                "file_path": class_file
            }
        
        return {"file_path": class_file}
        
    except Exception as e:
        return {"error": str(e)}


def generate_context_summary(method_info: Dict, class_info: Dict) -> str:
    """
    Generate a summary of the method context
    
    Original function: JavaCodeExtractor._generate_context_summary from code_extractor.py
    
    Args:
        method_info: Method information dictionary
        class_info: Class information dictionary
        
    Returns:
        Formatted context summary string
    """
    summary = f"Method: {method_info.get('method_name', 'Unknown')}\n"
    summary += f"Return type: {method_info.get('return_type', 'Unknown')}\n"
    summary += f"Modifiers: {method_info.get('modifiers', [])}\n"
    summary += f"Static: {method_info.get('is_static', False)}\n"
    
    if method_info.get('parameters'):
        summary += "Parameters:\n"
        for param in method_info['parameters']:
            summary += f"  - {param.get('type', 'Unknown')} {param.get('name', 'Unknown')}\n"
    
    if method_info.get('security_checks'):
        summary += f"Security checks: {', '.join(method_info['security_checks'])}\n"
    
    if method_info.get('exceptions'):
        summary += f"Exceptions: {', '.join(method_info['exceptions'])}\n"
    
    if class_info.get('extends'):
        summary += f"Inherits from: {class_info['extends']}\n"
    
    return summary

def extract_invoke_type(gadget: str) -> str:
    """
    Extract invoke type from gadget string
    
    Args:
        gadget: gadget string, format: [INVOKETYPE] <class:method> --(line:xxx, constraint:xxx)--> <next_class:next_method>
        
    Returns:
        str: invoke type, like "VIRTUAL", "STATIC", "SPECIAL" etc.
    """
    # Extract [INVOKETYPE] part
    invoke_type_match = re.match(r'\[([A-Z]+)\]', gadget)
    if invoke_type_match:
        invoke_type = invoke_type_match.group(1)
        # Add INVOKE prefix (if missing)
        if not invoke_type.startswith("INVOKE"):
            invoke_type = "INVOKE" + invoke_type
        return invoke_type
    return ""


def extract_method_signature(gadget: str) -> str:
    """
    Extract method signature from gadget string (only support new format)
    
    Args:
        gadget: gadget string
        
    Returns:
        str: extracted method signature, return empty string if cannot extract
    """
    # Only parse new format: [INVOKETYPE] <class:method> --(line:xxx, constraint:xxx)--> <next_class:next_method>
    new_format_pattern = r'\[[A-Z]+\]\s*<([^:]+):\s*([^>]+)>\s*--\(line:\d+,\s*constraint:\[[^\]]*\]\)-->\s*<([^:]+):\s*([^>]+)>'
    new_format_match = re.match(new_format_pattern, gadget)
    if new_format_match:
        return new_format_match.group(2).strip()
    return gadget
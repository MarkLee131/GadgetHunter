"""
Java Code Extractor
Main extraction interface combining all modular components

This module provides the unified interface for Java code extraction,
combining the functionality from the original code_extractor.py while
using the new modular structure.
"""

from typing import Dict, Any, List, Optional
from .parser import JavaCodeParser
from .file_locator import find_class_file, find_java_files
from ..analysis.code_analysis import (
    analyze_security_checks, extract_exceptions, extract_method_calls,
    get_class_info, generate_context_summary
)


class JavaCodeExtractor:
    """
    Unified Java code extractor using modular components
    
    This class maintains compatibility with the original JavaCodeExtractor
    while using the new modular structure for better organization.
    """
    
    def __init__(self, project_root: str = None, debug: bool = False):
        """
        Initialize the Java code extractor
        
        Args:
            project_root: Root directory of the project
            debug: Enable debug logging
        """
        self.project_root = project_root if project_root else ""
        self.debug = debug
        
        # Initialize the core parser
        self.parser = JavaCodeParser(project_root, debug)
        
        # Maintain compatibility
        self.java_files = []
        self.method_cache = {}
        self.tree_sitter_available = self.parser.tree_sitter_available
    
    def find_java_files(self, root_dir: str = None) -> List[str]:
        """
        Find all Java files in directory
        """
        if root_dir is None:
            root_dir = self.project_root
        
        self.java_files = find_java_files(root_dir)
        return self.java_files
    
    def extract_method_signature(self, full_signature: str, line_number: int = -1) -> Optional[Dict[str, Any]]:
        """
        Extract method signature and metadata using tree-sitter parser
        """
        return self.parser.extract_method_signature(full_signature, line_number)
    
    def extract_method_source(self, full_signature: str, line_number: int = -1) -> Optional[str]:
        """
        Extract source code for a specific method
        """
        return self.parser.extract_method_source(full_signature, line_number)
    
    def get_method_context(self, class_name: str, method_name: str) -> Dict[str, Any]:
        """
        Get comprehensive context for a method
        """
        method_info = self.extract_method_signature(f"<{class_name}: {method_name}>")
        if not method_info:
            return {"error": f"Method {class_name}.{method_name} not found"}
        
        # Get class information
        class_info = get_class_info(class_name, find_class_file(class_name, self.project_root, self.debug))
        
        return {
            "method": method_info,
            "class": class_info,
            "context": generate_context_summary(method_info, class_info)
        }
    
    def analyze_method_security(self, full_signature: str, line_number: int = -1) -> Dict[str, Any]:
        """
        Analyze method for security-related patterns
        
        Extended functionality combining multiple analysis functions
        """
        source_code = self.extract_method_source(full_signature, line_number)
        if not source_code:
            return {"error": "Could not extract source code"}
        
        analysis = {
            "signature": full_signature,
            "source_available": True,
            "security_checks": analyze_security_checks(source_code),
            "exceptions": extract_exceptions(source_code),
            "method_calls": extract_method_calls(source_code)
        }
        
        return analysis
    


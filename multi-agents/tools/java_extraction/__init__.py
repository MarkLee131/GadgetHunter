"""
Java Code Extraction Module

This module contains tightly coupled Java source code extraction functionality.
All components work together to provide comprehensive Java code analysis.

Main Components:
- parser.py: Core Tree-sitter Java parsing
- file_locator.py: Java file discovery and location
- signature_parser.py: Method signature parsing
- anonymous_handler.py: Anonymous class handling
- extractor.py: Unified extraction interface

Usage:
    from tools.java_extraction import JavaCodeExtractor
    
    extractor = JavaCodeExtractor(project_root)
    source = extractor.extract_method_source(signature, line_number)
"""

# Import main interface for easy access
from .extractor import JavaCodeExtractor

# Import specific components for advanced usage
from .parser import JavaCodeParser
from .file_locator import find_class_file, find_java_files
from .signature_parser import extract_source_signature, parse_method_signature
from .anonymous_handler import find_anonymous_classes, guess_anonymous_class_context, extract_inner_class_code

__all__ = [
    'JavaCodeExtractor',
    'JavaCodeParser',
    'find_class_file',
    'find_java_files',
    'extract_source_signature',
    'parse_method_signature',
    'find_anonymous_classes',
    'guess_anonymous_class_context',
    'extract_inner_class_code'
]
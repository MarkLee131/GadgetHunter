"""
Anonymous Class Handler
Functions for handling anonymous classes and inner classes

Original functions from: anon_class_context_extractor.py
"""

from tree_sitter import Language, Parser
import tree_sitter_java as tsjava
from typing import Dict, List, Any, Optional
from .file_locator import find_class_file


def find_anonymous_classes(java_file: str) -> List[Dict[str, Any]]:
    """
    use tree-sitter to traverse the Java file, return all anonymous classes' start and end line numbers and the parent node's context    
    Args:
        java_file: Path to Java file
        
    Returns:
        List of anonymous class information dictionaries
    """
    parser = Parser(Language(tsjava.language()))

    with open(java_file, 'r', encoding='utf-8') as f:
        code = f.read()

    tree = parser.parse(bytes(code, 'utf8'))
    root = tree.root_node

    results = []

    def get_enclosing_method_code(class_body_node, code):
        """
        Get enclosing method code for anonymous class
        """
        parent = class_body_node.parent
        while parent is not None:
            if parent.type == 'method_declaration':
                return code[parent.start_byte:parent.end_byte]
            parent = parent.parent
        return code[class_body_node.start_byte:class_body_node.end_byte]  # fallback: only return the anonymous class itself

    def walk(node, parent_context):
        """
        Walk AST to find anonymous classes
        """
        # match anonymous class: object_creation_expression + class_body
        if node.type == 'object_creation_expression':
            for child in node.children:
                if child.type == 'class_body':
                    start = child.start_point[0]
                    end = child.end_point[0]
                    method_code = get_enclosing_method_code(child, code)
                    results.append({
                        'lines': [start + 1, end + 1],  # convert to 1-based line numbers
                        'method_code': method_code,
                        'parent_context': parent_context
                    })
        
        # recursive traversal of all children
        for child in node.children:
            walk(child, f"{parent_context}.{node.type}")

    walk(root, "root")
    return results


def extract_code_slice(java_file: str, start_line: int, end_line: int, context_lines: int = 10) -> str:
    """
    extract the code slice within the specified line range, including context
    
    Args:
        java_file: Path to Java file
        start_line: Start line (1-based)
        end_line: End line (1-based)
        context_lines: Number of context lines to include
        
    Returns:
        Code slice as string
    """
    with open(java_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # calculate the actual start and end line (including context)
    actual_start = max(0, start_line - 1 - context_lines)
    actual_end = min(len(lines), end_line + context_lines)
    
    # extract the code slice
    code_slice = ''.join(lines[actual_start:actual_end])
    
    return code_slice


def guess_anonymous_class_context(class_name: str, project_root: str = "") -> Dict[str, Any]:
    """
    guess the context of anonymous classes, try to find the host class and extract the anonymous class code
    
    Args:
        class_name: Full class name with $ notation (e.g., com.example.Outer$1)
        project_root: Project root directory
        
    Returns:
        Dictionary with context information and anonymous class details
    """
    # 1. parse the class name, find the host class
    if '$' not in class_name:
        return {'error': f'Not an anonymous/inner class: {class_name}'}
    
    # hardcode the common host class mapping
    COMMON_ANONYMOUS_CLASS_CONTEXT = {
        'org.codehaus.groovy.runtime.dgm': 'DefaultGroovyMethods',
        # extendable
    }
    
    host_class = class_name.split('$')[0]
    
    # check the hardcode mapping
    for prefix, mapped_class in COMMON_ANONYMOUS_CLASS_CONTEXT.items():
        if host_class.startswith(prefix):
            host_class = f"{prefix}.{mapped_class}"
            break
    
    # 2. find the host class file
    host_class_file = find_class_file(host_class, project_root)
    
    if not host_class_file:
        return {'error': f'Host class file not found for: {host_class}'}
    
    # 3. find the anonymous classes in the host class file
    try:
        anonymous_classes = find_anonymous_classes(host_class_file)
        
        if not anonymous_classes:
            return {'error': f'No anonymous classes found in: {host_class_file}'}
        
        return {
            'host_class': host_class,
            'host_class_file': host_class_file,
            'anonymous_classes': anonymous_classes,
            'total_found': len(anonymous_classes),
            'note': 'These are possible anonymous class implementations, but the exact match is not guaranteed.'
        }
        
    except Exception as e:
        return {'error': f'Error processing {host_class_file}: {str(e)}'}


# keep the compatibility with the original file
COMMON_ANONYMOUS_CLASS_CONTEXT = {
    'org.codehaus.groovy.runtime.dgm': 'DefaultGroovyMethods',
    # extendable
}

def extract_inner_class_code(class_name: str, project_root: str = "") -> Dict[str, Any]:
    """
    Extract the code of the inner class or static nested class
    
    Args:
        class_name: Full class name with $ notation (e.g., com.example.Outer$Inner)
        project_root: Project root directory
        
    Returns:
        Dictionary with inner class information and code
    """
    # 1. Parse the class name to get outer class and inner class name
    if '$' not in class_name:
        return {'error': f'Not an inner class: {class_name}'}
    
    parts = class_name.split('$')
    outer_class = parts[0]
    inner_class_name = parts[1]
    
    # Skip if it's a numeric inner class (anonymous class)
    if inner_class_name.isdigit():
        return {'error': f'This appears to be an anonymous class, use guess_anonymous_class_context instead: {class_name}'}
    
    # 2. Find the outer class file
    outer_class_file = find_class_file(outer_class, project_root)
    
    if not outer_class_file:
        return {'error': f'Outer class file not found for: {outer_class}'}
    
    # 3. Search for inner class declaration in the outer class file
    try:
        with open(outer_class_file, 'r', encoding='utf-8') as f:
            content = f.read()
            lines = f.readlines()
        
        # Reset file pointer and read lines
        with open(outer_class_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Search patterns for inner class declarations
        import re
        
        # Pattern for regular inner class: "class InnerName"
        inner_class_pattern = rf'\b(?:public\s+|private\s+|protected\s+)?(?:static\s+)?class\s+{re.escape(inner_class_name)}\b'
        
        # Pattern for static nested class: "static class NestedName"
        static_nested_pattern = rf'\b(?:public\s+|private\s+|protected\s+)?static\s+class\s+{re.escape(inner_class_name)}\b'
        
        found_classes = []
        
        for i, line in enumerate(lines):
            line_stripped = line.strip()
            
            # Check for inner class declaration
            if re.search(inner_class_pattern, line_stripped) or re.search(static_nested_pattern, line_stripped):
                # Find the class body using tree-sitter for accurate extraction
                class_info = _extract_class_body_with_tree_sitter(outer_class_file, inner_class_name, i + 1)
                if class_info:
                    found_classes.append(class_info)
        
        if not found_classes:
            return {'error': f'Inner class "{inner_class_name}" not found in: {outer_class_file}'}
        
        return {
            'outer_class': outer_class,
            'outer_class_file': outer_class_file,
            'inner_class_name': inner_class_name,
            'inner_classes': found_classes,
            'total_found': len(found_classes)
        }
        
    except Exception as e:
        return {'error': f'Error processing {outer_class_file}: {str(e)}'}


def _extract_class_body_with_tree_sitter(java_file: str, class_name: str, approximate_line: int) -> Optional[Dict[str, Any]]:
    """
    Use tree-sitter to accurately extract the inner class body
    
    Args:
        java_file: Path to Java file
        class_name: Name of the inner class to find
        approximate_line: Approximate line number where class was found (1-based)
        
    Returns:
        Dictionary with class information or None if not found
    """
    try:
        parser = Parser(Language(tsjava.language()))
        
        with open(java_file, 'r', encoding='utf-8') as f:
            code = f.read()
        
        tree = parser.parse(bytes(code, 'utf8'))
        root = tree.root_node
        
        def find_class_declaration(node, target_name):
            """Recursively find class declaration by name"""
            if node.type == 'class_declaration':
                # Find the identifier node within class declaration
                for child in node.children:
                    if child.type == 'identifier' and child.text.decode('utf-8') == target_name:
                        start_line = node.start_point[0] + 1
                        end_line = node.end_point[0] + 1
                        class_code = code[node.start_byte:node.end_byte]
                        
                        return {
                            'lines': [start_line, end_line],
                            'code': class_code,
                            'type': 'inner_class'
                        }
            
            # Recursively search in children
            for child in node.children:
                result = find_class_declaration(child, target_name)
                if result:
                    return result
            
            return None
        
        return find_class_declaration(root, class_name)
        
    except Exception as e:
        print(f"[ERROR] Tree-sitter extraction failed: {e}")
        # Fallback to simple text extraction
        return _extract_class_body_simple(java_file, class_name, approximate_line)


def _extract_class_body_simple(java_file: str, class_name: str, approximate_line: int) -> Optional[Dict[str, Any]]:
    """
    Simple fallback method to extract class body using brace matching
    
    Args:
        java_file: Path to Java file
        class_name: Name of the inner class to find
        approximate_line: Approximate line number where class was found (1-based)
        
    Returns:
        Dictionary with class information or None if not found
    """
    try:
        with open(java_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Start from the approximate line and find the opening brace
        start_line = approximate_line - 1  # Convert to 0-based
        brace_count = 0
        class_start = start_line
        class_end = len(lines)
        
        # Find the opening brace of the class
        for i in range(start_line, len(lines)):
            line = lines[i]
            if '{' in line:
                class_start = i
                brace_count = line.count('{') - line.count('}')
                break
        
        # Find the closing brace
        for i in range(class_start + 1, len(lines)):
            line = lines[i]
            brace_count += line.count('{') - line.count('}')
            if brace_count == 0:
                class_end = i + 1
                break
        
        # Extract the class code
        class_lines = lines[class_start:class_end]
        class_code = ''.join(class_lines)
        
        return {
            'lines': [class_start + 1, class_end],  # Convert back to 1-based
            'code': class_code,
            'type': 'inner_class'
        }
        
    except Exception as e:
        print(f"[ERROR] Simple extraction failed: {e}")
        return None



# usage example
if __name__ == '__main__':
    import sys
    if len(sys.argv) != 3:
        print("Usage: python anonymous_handler.py <fully.qualified.Class$N> <project_src_root>")
        sys.exit(1)
    class_name, project_root = sys.argv[1], sys.argv[2]
    result = guess_anonymous_class_context(class_name=class_name, project_root=project_root)
    print(f"Found {len(result['anonymous_classes'])} anonymous classes in {result['host_class_file']}")
    for i, anon in enumerate(result['anonymous_classes'][:3]):
        print(f"Anonymous class #{i+1} (lines {anon['lines']}):")
        print(anon['method_code']) 
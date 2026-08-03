"""
Java Code Parser
Core Java code parsing functionality using Tree-sitter

Original functions from: code_extractor.py
"""

import os
import json
from typing import Dict, Any, List, Optional
from tree_sitter import Language, Parser, Query, QueryCursor
import tree_sitter_java as tsjava
from ..core.config import Config
from .file_locator import find_class_file
from .anonymous_handler import guess_anonymous_class_context, extract_inner_class_code

config = Config()


class JavaCodeParser:
    """
    Core Java code parser using Tree-sitter
    
    Original class: JavaCodeExtractor from code_extractor.py
    """
    
    def __init__(self, project_root: str = None, debug: bool = None):
        """
        Initialize Java parser with Tree-sitter
        
        Original function: JavaCodeExtractor.__init__ from code_extractor.py
        """
        self.project_root = project_root if project_root else ""
        self.java_files = []
        self.method_cache = {}
        self.debug = debug if debug is not None else config.debug
        self.extract_javadoc = config.extract_javadoc
        
        try:
            self.language = Language(tsjava.language())
            self.parser = Parser(self.language)
            print("[JavaCodeParser] Tree-sitter (pip package, 0.20.x API) initialized successfully")
            self.tree_sitter_available = True
        except Exception as e:
            print(f"[JavaCodeParser] Failed to initialize Tree-sitter (pip package): {e}")
            self.tree_sitter_available = False
    
    def find_java_files(self, root_dir: str = None) -> List[str]:
        """
        Find all Java files in directory
        
        Original function: JavaCodeExtractor._find_java_files from code_extractor.py
        """
        if root_dir is None:
            root_dir = self.project_root
        
        java_files = []
        for root, dirs, files in os.walk(root_dir):
            for file in files:
                if file.endswith('.java'):
                    java_files.append(os.path.join(root, file))
        
        self.java_files = java_files
        return java_files
    
    def extract_method_signature(self, full_signature: str, line_number: int = -1) -> Optional[Dict[str, Any]]:
        """
        Extract method signature and metadata using tree-sitter parser
        
        Original function: JavaCodeExtractor.extract_method_signature from code_extractor.py
        
        Args:
            full_signature: Full method signature, e.g. <class: returnType methodName(paramType1,...)>
            line_number: Optional, the expected starting line number of the method (1-based). If -1, ignored.
        Returns:
            Dict with method info, or None if not found.
        """
        if self.debug:
            print(f"[DEBUG][extract_method_signature] tree_sitter_available={self.tree_sitter_available}, full_signature={full_signature}, line_number={line_number}")
        
        if not self.tree_sitter_available:
            if self.debug:
                print(f"[ERROR] Tree-sitter not available, cannot extract method signature")
            return None
            
        result = self._extract_with_tree_sitter(full_signature, line_number)
        
        # If _tree_sitter returns None and it is an anonymous/inner class, try anon_class_context_extractor
        if result is None:
            import re
            m = re.match(r'<(.+?):', full_signature)
            class_name = m.group(1) if m else None
            if class_name and '$' in class_name:
                print(f"[INFO] Fallback to anonymous/inner class extraction for {class_name}")
                
                # Determine if it's an anonymous class (numeric after $) or inner class (named after $)
                parts = class_name.split('$')
                if len(parts) > 1 and parts[1].isdigit():
                    # Anonymous class
                    try:
                        context_result = guess_anonymous_class_context(class_name, self.project_root)
                        if 'anonymous_classes' in context_result and context_result['anonymous_classes']:
                            print(f"[INFO] Extracted {len(context_result['anonymous_classes'])} anonymous class contexts from {context_result['host_class_file']}")
                            note = context_result.get('note', 'These are possible anonymous class implementations, but the exact match is not guaranteed.')
                            return {
                                'method_name': f'anonymous_class_{class_name}',
                                'body': context_result['anonymous_classes'][0]['method_code'],
                                'context_info': context_result,
                                'note': note
                            }
                        else:
                            print(f"[WARN] No anonymous class context found for {class_name}")
                    except Exception as e:
                        print(f"[ERROR] Failed to extract anonymous class context for {class_name}: {e}")
                else:
                    # Inner class
                    try:
                        inner_result = extract_inner_class_code(class_name, self.project_root)
                        if 'inner_classes' in inner_result and inner_result['inner_classes']:
                            print(f"[INFO] Extracted {len(inner_result['inner_classes'])} inner class definitions from {inner_result['outer_class_file']}")
                            return {
                                'method_name': f'inner_class_{class_name}',
                                'body': inner_result['inner_classes'][0]['code'],
                                'context_info': inner_result
                            }
                        else:
                            print(f"[WARN] No inner class found for {class_name}")
                    except Exception as e:
                        print(f"[ERROR] Failed to extract inner class for {class_name}: {e}")
                        # Fallback to anonymous class extraction
                        try:
                            context_result = guess_anonymous_class_context(class_name, self.project_root)
                            if 'anonymous_classes' in context_result and context_result['anonymous_classes']:
                                print(f"[INFO] Fallback: Extracted {len(context_result['anonymous_classes'])} anonymous class contexts from {context_result['host_class_file']}")
                                note = context_result.get('note', 'These are possible anonymous class implementations, but the exact match is not guaranteed.')
                                return {
                                    'method_name': f'fallback_anonymous_class_{class_name}',
                                    'body': context_result['anonymous_classes'][0]['method_code'],
                                    'context_info': context_result,
                                    'note': note
                                }
                        except Exception as fallback_e:
                            print(f"[ERROR] Fallback extraction also failed for {class_name}: {fallback_e}")
        
        return result
    
    def extract_method_source(self, full_signature: str, line_number: int = -1) -> Optional[str]:
        """
        Extract source code for a specific method, given a full method signature
        
        Original function: JavaCodeExtractor.extract_method_source from code_extractor.py
        
        Args:
            full_signature: Full method signature, e.g. <class: returnType methodName(paramType1,...)>
            line_number: Optional, the expected starting line number of the method (1-based). If -1, ignored.
        Returns:
            Source code string, or None if not found.
        """
        method_info = self.extract_method_signature(full_signature, line_number)
        if method_info:
            # Prefer to return the body of the normal method
            if 'body' in method_info:
                if self.extract_javadoc and 'start_byte' in method_info and 'code' in method_info:
                    comment = self._extract_javadoc_before(method_info['code'], method_info['start_byte'])
                    if comment:
                        return comment + '\n' + method_info['body']
                return method_info['body']
            # If it is an anonymous class, return all bodies
            if 'bodies' in method_info:
                return method_info['bodies']
        return None
    
        # [2025-07-21 19:25:30] Refactor: Accept full_signature, parse class/method info internally
    def _extract_with_tree_sitter(self, full_signature: str, line_number: int = -1) -> Optional[Dict[str, Any]]:
        """
        Extract method info using tree-sitter, matching by full signature first. If multiple matches, use line_number to disambiguate.
        Matching strategy:
        1. Try to match method by class, name, param types, and return type (normalized).
        2. If no match, fallback to short-name match (method name, param short names, return type short name).
        3. If multiple short-name matches, use line_number to disambiguate.
        """
        if self.debug:
            print(f"[DEBUG][TreeSitter] _extract_with_tree_sitter called for {full_signature}, line_number={line_number}")
        # Parse signature to get class_name, method_name, etc.
        import re
        def parse_signature(signature):
            if self.debug:
                print(f"[DEBUG][parse_signature] Input signature: '{signature}'")
                print(f"[DEBUG][parse_signature] Signature length: {len(signature)}")
                print(f"[DEBUG][parse_signature] Signature repr: {repr(signature)}")
            
            m = re.match(r'<(.+?):\s+(\S+)\s+(\w+)\((.*)\)>', signature)
            if m:
                class_name, return_type, method_name, param_str = m.groups()
                param_types = [p.strip() for p in param_str.split(',')] if param_str.strip() else []
                if self.debug:
                    print(f"[DEBUG][parse_signature] SUCCESS - Full match: class={class_name}, return={return_type}, method={method_name}, params={param_types}")
                return class_name, return_type, method_name, param_types
            
            if self.debug:
                print(f"[DEBUG][parse_signature] Full pattern failed, trying simple pattern")
            
            m2 = re.match(r'(\S+)\s+(\w+)\((.*)\)', signature)
            if m2:
                return_type, method_name, param_str = m2.groups()
                param_types = [p.strip() for p in param_str.split(',')] if param_str.strip() else []
                if self.debug:
                    print(f"[DEBUG][parse_signature] SUCCESS - Simple match: return={return_type}, method={method_name}, params={param_types}")
                return None, return_type, method_name, param_types
            
            if self.debug:
                print(f"[DEBUG][parse_signature] Both patterns failed!")
                # Test the patterns manually
                # full_pattern = r'<(.+?):\s+(\S+)\s+(\w+)\((.*)\)>'
                # simple_pattern = r'(\S+)\s+(\w+)\((.*)\)'
                # print(f"[DEBUG][parse_signature] Testing full pattern: {re.match(full_pattern, signature) is not None}")
                # print(f"[DEBUG][parse_signature] Testing simple pattern: {re.match(simple_pattern, signature) is not None}")
            
            raise ValueError(f"Invalid signature: {signature}")
        def short_type(type_str):
            if not type_str:
                return ''
            type_str = type_str.split('<')[0]
            type_str = type_str.replace('[]', '')
            return type_str.strip().split('.')[-1]
        def short_signature(method_name, param_types, return_type):
            short_params = [short_type(p) for p in param_types]
            short_ret = short_type(return_type)
            return method_name, short_params, short_ret
        # === Generic type parameter erasing related functions ===
        def collect_type_params(class_node, code):
            """
            Collect type parameters and their upper bounds from class declaration, return dict, like {'K': 'Object', 'V': 'Object', 'T': 'Number'}
            """
            type_params = {}
            for c in class_node.children:
                # print(f"[DEBUG][collect_type_params] child type: {c.type}, text: {code[c.start_byte:c.end_byte]}")
                if c.type == 'type_parameters':
                    for tp in c.children:
                        # print(f"[DEBUG][collect_type_params] type_parameter node: {tp.type}, text: {code[tp.start_byte:tp.end_byte]}")
                        if tp.type == 'type_parameter':
                            # Parse type parameter name
                            name = None
                            bound = 'Object'
                            for tpc in tp.children:
                                # print(f"[DEBUG][collect_type_params] type_parameter child: {tpc.type}, text: {code[tpc.start_byte:tpc.end_byte]}")
                                if tpc.type in ('identifier', 'type_identifier'):
                                    name = code[tpc.start_byte:tpc.end_byte]
                                if tpc.type == 'type_bound':
                                    # Only take the first upper bound
                                    for bc in tpc.children:
                                        # print(f"[DEBUG][collect_type_params] type_bound child: {bc.type}, text: {code[bc.start_byte:bc.end_byte]}")
                                        if bc.type in ('type_identifier', 'integral_type', 'floating_point_type'):
                                            bound = code[bc.start_byte:bc.end_byte]
                                            break
                            if name:
                                type_params[name] = bound
                                # print(f"[DEBUG][collect_type_params] type_param added: {name} -> {bound}")
            return type_params
        def erase_java_type(param_type, type_params):
            """
            param_type: str, like 'K', 'V', 'List<K>', 'Map<K,V>', 'int' etc.
            type_params: dict, like {'K': 'Object', 'V': 'Object', 'T': 'Number'}
            return erased type string
            """
            import re
            def erase(t):
                # print(f"[DEBUG][erase_java_type] t: {t}, type_params: {type_params}")
                m = re.match(r'(\w+)<(.+)>', t)
                if m:
                    base = m.group(1)
                    # Keep the original class name after erasing generic types
                    return base
                return type_params.get(t, t)
            return erase(param_type)
        # === END Generic type parameter erasing related functions ===
        try:
            if self.debug:
                print(f"[DEBUG][_extract_with_tree_sitter] About to parse signature: '{full_signature}'")
                print(f"[DEBUG][_extract_with_tree_sitter] Full signature repr: {repr(full_signature)}")
            
            class_name, target_return_type, target_method_name, target_param_types = parse_signature(full_signature)
        except Exception as e:
            if self.debug:
                print(f"[DEBUG][TreeSitter] Signature parse error: {e}")
            return None
        if not class_name:
            if self.debug:
                print(f"[DEBUG][TreeSitter] No class_name parsed from signature: {full_signature}")
            return None
        class_file = find_class_file(class_name, self.project_root, self.debug)
        if not class_file:
            if '$' in class_name:
                print(f"[WARN] Class {class_name} is an anonymous or inner class. Source file does not exist.")
                
                # Determine if it's an anonymous class (numeric after $) or inner class (named after $)
                parts = class_name.split('$')
                if len(parts) > 1 and parts[1].isdigit():
                    # Anonymous class - use existing logic
                    try:
                        context_result = guess_anonymous_class_context(class_name, self.project_root)
                        if 'anonymous_classes' in context_result and context_result['anonymous_classes']:
                            print(f"[INFO] Extracted {len(context_result['anonymous_classes'])} anonymous class contexts from {context_result['host_class_file']}")
                            note = context_result.get('note', 'These are possible anonymous class implementations, but the exact match is not guaranteed.')
                            # Return all anonymous class contexts with uncertainty note
                            return {
                                'method_name': f'anonymous_class_{class_name}',
                                'bodies': [anon['method_code'] for anon in context_result['anonymous_classes']],
                                'context_info': context_result,
                                'note': note
                            }
                        else:
                            print(f"[WARN] No anonymous class context found for {class_name}")
                    except Exception as e:
                        print(f"[ERROR] Failed to extract anonymous class context for {class_name}: {e}")
                else:
                    # Inner class - use new inner class extraction
                    try:
                        inner_result = extract_inner_class_code(class_name, self.project_root)
                        if 'inner_classes' in inner_result and inner_result['inner_classes']:
                            print(f"[INFO] Extracted {len(inner_result['inner_classes'])} inner class definitions from {inner_result['outer_class_file']}")
                            # Return inner class code
                            return {
                                'method_name': f'inner_class_{class_name}',
                                'bodies': [inner['code'] for inner in inner_result['inner_classes']],
                                'context_info': inner_result
                            }
                        else:
                            print(f"[WARN] No inner class found for {class_name}")
                    except Exception as e:
                        print(f"[ERROR] Failed to extract inner class for {class_name}: {e}")
                        # Fallback to anonymous class extraction in case of error
                        try:
                            context_result = guess_anonymous_class_context(class_name, self.project_root)
                            if 'anonymous_classes' in context_result and context_result['anonymous_classes']:
                                print(f"[INFO] Fallback: Extracted {len(context_result['anonymous_classes'])} anonymous class contexts from {context_result['host_class_file']}")
                                note = context_result.get('note', 'These are possible anonymous class implementations, but the exact match is not guaranteed.')
                                return {
                                    'method_name': f'fallback_anonymous_class_{class_name}',
                                    'bodies': [anon['method_code'] for anon in context_result['anonymous_classes']],
                                    'context_info': context_result,
                                    'note': note
                                }
                        except Exception as fallback_e:
                            print(f"[ERROR] Fallback extraction also failed for {class_name}: {fallback_e}")
            else:
                print(f"[WARN] Source file for class {class_name} not found.")
            return None
        try:
            with open(class_file, 'r', encoding='utf-8') as f:
                code = f.read()
            if self.debug:
                print(f"[DEBUG][TreeSitter] Input method_signature: {full_signature}")
                print(f"[DEBUG][TreeSitter] Will search file: {class_file}")
            tree = self.parser.parse(bytes(code, 'utf8'))
            root_node = tree.root_node
            query_str = """
                (method_declaration
                    type: (_) @return-type
                    name: (identifier) @method-name
                    parameters: (formal_parameters) @params
                )
            """
            query = Query(self.language, query_str)
            cursor = QueryCursor(query)
            matches = cursor.captures(root_node)
            def normalize_type(type_str):
                type_str = type_str.replace('final ', '').replace('volatile ', '').replace('transient ', '')
                type_str = re.sub(r'<.*?>', '', type_str)
                type_str = type_str.replace('[]', '').strip()
                simple = type_str.split('.')[-1]
                return type_str
            # Collect type parameters first
            type_params = {}
            for child in root_node.children:
                if child.type == 'class_declaration':
                    # print(f"[DEBUG][class_declaration] text: {code[child.start_byte:child.end_byte]}")
                    # for c in child.children:
                    #     print(f"[DEBUG][class_declaration child] type: {c.type}, text: {code[c.start_byte:c.end_byte]}")
                    class_id_node = None
                    for c in child.children:
                        if c.type == 'identifier':
                            class_id_node = c
                            break
                    class_id = code[class_id_node.start_byte:class_id_node.end_byte] if class_id_node else None
                    # print(f"[DEBUG][class_id] class_id: {class_id}, expected: {class_name.split('.')[-1]}")
                    if class_id == class_name.split('.')[-1]:
                        type_params = collect_type_params(child, code)
                        if self.debug:
                            print(f"[DEBUG][TreeSitter] Collected type_params: {type_params}")
                        break
            # Erase gadget chain target parameter types
            target_param_types = [normalize_type(p) for p in target_param_types]
            erased_target_param_types = [erase_java_type(p, type_params) for p in target_param_types]
            # if self.debug:
                # print(f"[DEBUG][TreeSitter] target_param_types: {target_param_types} -> erased_target_param_types: {erased_target_param_types}")
            target_return_type = normalize_type(target_return_type)
            erased_target_return_type = erase_java_type(target_return_type, type_params)
            candidates = []
            short_candidates = []
            for child in root_node.children:
                if child.type == 'class_declaration':
                    class_id_node = None
                    for c in child.children:
                        if c.type == 'identifier':
                            class_id_node = c
                            break
                    class_id = code[class_id_node.start_byte:class_id_node.end_byte] if class_id_node else None
                    if class_id != class_name.split('.')[-1]:
                        continue
                    def collect_methods(node):
                        for child in node.children:
                            if child.type == 'method_declaration':
                                method_decl_node = child
                                method_node = None
                                params_node = None
                                return_type_node = None
                                for c in child.children:
                                    if c.type == 'identifier':
                                        method_node = c
                                    if c.type == 'formal_parameters':
                                        params_node = c
                                    if c.type in (
                                        'type_identifier', 'void_type', 'integral_type', 'floating_point_type',
                                        'primitive_type', 'boolean_type', 'numeric_type', 'reference_type', 'unannotated_type', 'basic_type'
                                    ):
                                        return_type_node = c
                                # If no return type node found, debug print all child node types and content
                                # if return_type_node is None and self.debug:
                                    # for c in child.children:
                                        # print(f"[DEBUG][method_declaration child] type: {c.type}, text: {code[c.start_byte:c.end_byte]}")
                                if not method_node:
                                    continue
                                method_node_text = code[method_node.start_byte:method_node.end_byte]
                                param_types = []
                                if params_node:
                                    for param in params_node.children:
                                        if param.type == 'formal_parameter':
                                            type_node = param.child_by_field_name('type')
                                            if type_node is not None:
                                                param_type = code[type_node.start_byte:type_node.end_byte]
                                            else:
                                                param_type = '[NO TYPE FOUND]'
                                            param_types.append(normalize_type(param_type))
                                # Erase generic type parameters
                                erased_param_types = [erase_java_type(t, type_params) for t in param_types]
                                # if self.debug:
                                    # print(f"[DEBUG][TreeSitter] param_types: {param_types} -> erased_param_types: {erased_param_types}")
                                ret_type_raw = ''
                                if return_type_node:
                                    ret_type_raw = code[return_type_node.start_byte:return_type_node.end_byte].strip()
                                    if (return_type_node.type == 'void_type' or ret_type_raw == ''):
                                        ret_type_raw = 'void'
                                else:
                                    if method_decl_node:
                                        for c in method_decl_node.children:
                                            if c.type == 'void_type':
                                                ret_type_raw = 'void'
                                                break
                                            elif c.type == 'type_identifier':
                                                ret_type_raw = code[c.start_byte:c.end_byte].strip()
                                                break
                                ret_type = normalize_type(ret_type_raw)
                                erased_ret_type = erase_java_type(ret_type, type_params)
                                method_start_line = method_decl_node.start_point[0] + 1 if method_decl_node is not None else -1
                                method_end_line = method_decl_node.end_point[0] + 1 if method_decl_node is not None else -1
                                # Full comparison (after erasing generic types)
                                sig_match = (
                                    method_node_text == target_method_name and
                                    len(erased_param_types) == len(erased_target_param_types) and
                                    all(a == b for a, b in zip(erased_param_types, erased_target_param_types)) and
                                    erased_ret_type == erased_target_return_type
                                )
                                # Short comparison
                                short_method, short_params, short_ret = short_signature(method_node_text, erased_param_types, erased_ret_type)
                                short_target_method, short_target_params, short_target_ret = short_signature(target_method_name, erased_target_param_types, erased_target_return_type)
                                short_sig_match = (
                                    short_method == short_target_method and
                                    len(short_params) == len(short_target_params) and
                                    all(a == b for a, b in zip(short_params, short_target_params)) and
                                    short_ret == short_target_ret
                                )
                                # if self.debug:
                                #     print(f"[DEBUG][TreeSitter] Candidate: {method_node_text}({erased_param_types}) -> {erased_ret_type}, lines [{method_start_line}, {method_end_line}]")
                                #     print(f"[DEBUG][TreeSitter] Gadget expects: {target_method_name}({erased_target_param_types}) -> {erased_target_return_type}")
                                #     print(f"[DEBUG][TreeSitter] Short candidate: {short_method}({short_params}) -> {short_ret}")
                                #     print(f"[DEBUG][TreeSitter] Short gadget expects: {short_target_method}({short_target_params}) -> {short_target_ret}")
                                if sig_match:
                                    candidates.append((method_decl_node, method_node_text, erased_param_types, erased_ret_type, method_start_line, method_end_line))
                                elif short_sig_match:
                                    short_candidates.append((method_decl_node, method_node_text, erased_param_types, erased_ret_type, method_start_line, method_end_line))
                            else:
                                collect_methods(child)
                    collect_methods(child)
            # Prefer full comparison
            if candidates:
                if line_number == -1 or len(candidates) == 1:
                    chosen = candidates[0]
                    if self.debug:
                        print(f"[DEBUG][TreeSitter] Unique signature match (or no line info), returning method: {chosen[1]}({chosen[2]}) -> {chosen[3]} at [{chosen[4]}, {chosen[5]}]")
                    method_decl_node, method_node_text, param_types, ret_type, method_start_line, method_end_line = chosen
                    start_byte = method_decl_node.start_byte
                    end_byte = method_decl_node.end_byte
                    return {
                        'method_name': method_node_text,
                        'body': code[start_byte:end_byte],
                        'start_byte': start_byte,
                        'end_byte': end_byte,
                        'code': code
                    }
                # Multiple matches, use line number to filter
                best_candidate = None
                best_start_line = -1
                for cand in candidates:
                    method_decl_node, method_node_text, param_types, ret_type, method_start_line, method_end_line = cand
                    if method_start_line <= line_number <= method_end_line:
                        if method_start_line > best_start_line:
                            best_candidate = cand
                            best_start_line = method_start_line
                if best_candidate:
                    if self.debug:
                        print(f"[DEBUG][TreeSitter] Multiple matches, using line number. Returning method: {best_candidate[1]}({best_candidate[2]}) -> {best_candidate[3]} at [{best_candidate[4]}, {best_candidate[5]}]")
                    method_decl_node, method_node_text, param_types, ret_type, method_start_line, method_end_line = best_candidate
                    start_byte = method_decl_node.start_byte
                    end_byte = method_decl_node.end_byte
                    return {
                        'method_name': method_node_text,
                        'body': code[start_byte:end_byte],
                        'start_byte': start_byte,
                        'end_byte': end_byte,
                        'code': code
                    }
                if self.debug:
                    print(f"[DEBUG][TreeSitter] Multiple matches, but no candidate covers line {line_number}.")
                return None
            # Use short comparison
            if short_candidates:
                if line_number == -1 or len(short_candidates) == 1:
                    chosen = short_candidates[0]
                    # if self.debug:
                        # print(f"[DEBUG][TreeSitter] Short signature match (or no line info), returning method: {chosen[1]}({chosen[2]}) -> {chosen[3]} at [{chosen[4]}, {chosen[5]}]")
                    method_decl_node, method_node_text, param_types, ret_type, method_start_line, method_end_line = chosen
                    start_byte = method_decl_node.start_byte
                    end_byte = method_decl_node.end_byte
                    return {
                        'method_name': method_node_text,
                        'body': code[start_byte:end_byte],
                        'start_byte': start_byte,
                        'end_byte': end_byte,
                        'code': code
                    }
                # Multiple short matches, use line number to filter
                best_candidate = None
                best_start_line = -1
                for cand in short_candidates:
                    method_decl_node, method_node_text, param_types, ret_type, method_start_line, method_end_line = cand
                    if method_start_line <= line_number <= method_end_line:
                        if method_start_line > best_start_line:
                            best_candidate = cand
                            best_start_line = method_start_line
                if best_candidate:
                    # if self.debug:
                        # print(f"[DEBUG][TreeSitter] Multiple short matches, using line number. Returning method: {best_candidate[1]}({best_candidate[2]}) -> {best_candidate[3]} at [{best_candidate[4]}, {best_candidate[5]}]")
                    method_decl_node, method_node_text, param_types, ret_type, method_start_line, method_end_line = best_candidate
                    start_byte = method_decl_node.start_byte
                    end_byte = method_decl_node.end_byte
                    return {
                        'method_name': method_node_text,
                        'body': code[start_byte:end_byte],
                        'start_byte': start_byte,
                        'end_byte': end_byte,
                        'code': code
                    }
                if self.debug:
                    print(f"[DEBUG][TreeSitter] Multiple short matches, but no candidate covers line {line_number}.")
                return None
            if self.debug:
                print(f"[DEBUG][TreeSitter] No matching method found for {class_name}.{full_signature} (even after short signature match)")
            return None
        except Exception as e:
            if self.debug:
                print(f"[CodeExtractor][TreeSitter] Error: {e}")
            return None
    
    def save_extraction_cache(self, cache_file: str = "method_cache.json"):
        """
        Save method extraction cache to file
        
        Original function: JavaCodeExtractor.save_extraction_cache from code_extractor.py
        """
        try:
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.method_cache, f, ensure_ascii=False, indent=2)
            print(f"[JavaCodeParser] Cache saved to {cache_file}")
        except Exception as e:
            print(f"[JavaCodeParser] Failed to save cache: {e}")
    
    def load_extraction_cache(self, cache_file: str = "method_cache.json"):
        """
        Load method extraction cache from file
        
        Original function: JavaCodeExtractor.load_extraction_cache from code_extractor.py
        """
        try:
            if os.path.exists(cache_file):
                with open(cache_file, 'r', encoding='utf-8') as f:
                    self.method_cache = json.load(f)
                print(f"[JavaCodeParser] Cache loaded from {cache_file}")
        except Exception as e:
            print(f"[JavaCodeParser] Failed to load cache: {e}")
    
    def _extract_javadoc_before(self, code: str, start_byte: int) -> str:
        """
        Extract Javadoc immediately before the method declaration (/** ... */), allowing whitespace in between
        """
        import re
        before = code[:start_byte]
        # Find all Javadoc blocks
        javadocs = list(re.finditer(r'/\*\*.*?\*/', before, re.DOTALL))
        if javadocs:
            last_javadoc = javadocs[-1]
            # Check if there is only whitespace between the Javadoc and the method declaration
            between = before[last_javadoc.end():]
            if all(c in ' \t\r\n' for c in between):
                return before[last_javadoc.start():start_byte].rstrip()
        
        # Find consecutive // comments (also require immediately before the method declaration)
        lines = before.splitlines()
        comment_lines = []
        for line in reversed(lines):
            if line.strip().startswith('//'):
                comment_lines.append(line)
            elif line.strip() == '':
                continue
            else:
                break
        
        # Only return if there is only whitespace after the comments
        if comment_lines:
            # Check if there is only whitespace between the comments and the method declaration
            idx = len(lines) - len(comment_lines)
            between_lines = lines[idx:]
            if all(l.strip() == '' or l.strip().startswith('//') for l in between_lines):
                return '\n'.join(reversed(comment_lines))
        
        return ''
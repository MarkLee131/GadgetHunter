"""
Java File Locator
Utilities for finding and locating Java source files
"""

import os
from typing import Optional
from ..core.config import JDK_DIR


def find_class_file(class_name: str, project_root: str = "", debug: bool = False) -> Optional[str]:
    """
    Find Java file for the given class name, with debug logging and $ Annonymous class handling
    
    Args:
        class_name: Full class name (e.g., com.example.MyClass or com.example.MyClass$InnerClass)
        project_root: Project root directory
        debug: Enable debug logging
        
    Returns:
        Path to Java file or None if not found
    """
    main_class = class_name.split('$')[0]
    file_name = main_class.replace('.', '/') + '.java'
    
    if debug:
        print(f"[DEBUG][find_class_file] Looking for class: {class_name}")
        print(f"[DEBUG][find_class_file] Main class: {main_class}")
        print(f"[DEBUG][find_class_file] File name: {file_name}")
        print(f"[DEBUG][find_class_file] Project root: {project_root}")
    
    # 1. Look for project source code first
    if project_root:
        abs_path = os.path.join(project_root, file_name)
        if debug:
            print(f"[DEBUG][find_class_file] Checking project path: {abs_path}")
        if os.path.exists(abs_path):
            if debug:
                print(f"[DEBUG][find_class_file] Found in project: {abs_path}")
            return abs_path
    
    # 2. Look for jdk source code (only if GADGETHUNTER_JDK_DIR is set)
    if JDK_DIR:
        jdk_src_root = os.path.join(JDK_DIR, 'jdk8u', 'jdk', 'src', 'share', 'classes')
        abs_path = os.path.join(jdk_src_root, file_name)
        if os.path.exists(abs_path):
            return abs_path
    
    # 3. Recursively search all .java files 
    if debug:
        print(f"[DEBUG][find_class_file] Recursively searching in project root...")
    candidates = []
    for root, dirs, files in os.walk(project_root):
        for file in files:
            if file.endswith('.java'):
                full_path = os.path.join(root, file)
                candidates.append(full_path)
    
    if debug:
        print(f"[DEBUG][find_class_file] Found {len(candidates)} Java files")
    
    # 4. Exact file name matching
    for java_file in candidates:
        if java_file.endswith(file_name):
            if debug:
                print(f"[DEBUG][find_class_file] Found exact match: {java_file}")
            return java_file
    
    # 5. Simple class name matching
    simple_class_name = main_class.split('.')[-1]
    for java_file in candidates:
        if os.path.basename(java_file) == f"{simple_class_name}.java":
            if debug:
                print(f"[DEBUG][find_class_file] Found simple match: {java_file}")
            return java_file
    
    if debug:
        print(f"[DEBUG][find_class_file] No file found for {class_name}")
    return None


def find_java_files(root_dir: str) -> list:
    """
    Find all Java files in directory
    
    Args:
        root_dir: Root directory to search
        
    Returns:
        List of Java file paths
    """
    java_files = []
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if file.endswith('.java'):
                java_files.append(os.path.join(root, file))
    return java_files
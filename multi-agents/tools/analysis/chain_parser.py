"""
Chain File Parser
Utilities for parsing gadget chain files

Original functions from: chain_utils.py
"""

from typing import List


def parse_chains_file(chains_file: str) -> List[List[str]]:
    """
    Read chains file and split by empty lines into multiple chains
    
    Args:
        chains_file: Path to chains file
        
    Returns:
        List of chains, where each chain is a list of edge strings
        
    Example:
        Input file content:
        ```
        [VIRTUAL] <Class1: method1()> --> <Class2: method2()>
        [VIRTUAL] <Class2: method2()> --> <Class3: method3()>
        
        [VIRTUAL] <ClassA: methodA()> --> <ClassB: methodB()>
        ```
        
        Returns:
        [
            ["[VIRTUAL] <Class1: method1()> --> <Class2: method2()>", 
             "[VIRTUAL] <Class2: method2()> --> <Class3: method3()>"],
            ["[VIRTUAL] <ClassA: methodA()> --> <ClassB: methodB()>"]
        ]
    """
    chains = []
    current_chain = []
    
    with open(chains_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                # Empty line indicates end of current chain
                if current_chain:
                    chains.append(current_chain)
                    current_chain = []
            elif not line.startswith('total gadget chains'):
                current_chain.append(line)
    
    # Add the last chain if file doesn't end with empty line
    if current_chain:
        chains.append(current_chain)
    
    return chains


def count_chains_in_file(chains_file: str) -> int:
    """
    Count the number of chains in a chains file without loading all data
    
    Extended functionality for chain file operations
    
    Args:
        chains_file: Path to chains file
        
    Returns:
        Number of chains in the file
    """
    count = 0
    in_chain = False
    
    with open(chains_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                if not in_chain:
                    count += 1
                    in_chain = True
            else:
                in_chain = False
    
    return count


def validate_chain_file(chains_file: str) -> dict:
    """
    Validate a chains file and return statistics
    
    Extended functionality for chain file operations
    
    Args:
        chains_file: Path to chains file
        
    Returns:
        Dictionary with validation results and statistics
    """
    try:
        chains = parse_chains_file(chains_file)
        
        total_chains = len(chains)
        total_edges = sum(len(chain) for chain in chains)
        empty_chains = sum(1 for chain in chains if len(chain) == 0)
        
        # Check for valid edge format
        invalid_edges = []
        for chain_idx, chain in enumerate(chains):
            for edge_idx, edge in enumerate(chain):
                if '<' not in edge or '>' not in edge:
                    invalid_edges.append(f"Chain {chain_idx}, Edge {edge_idx}: {edge}")
        
        return {
            'valid': True,
            'total_chains': total_chains,
            'total_edges': total_edges,
            'empty_chains': empty_chains,
            'invalid_edges': invalid_edges,
            'average_chain_length': total_edges / total_chains if total_chains > 0 else 0
        }
        
    except Exception as e:
        return {
            'valid': False,
            'error': str(e)
        }


def parse_chains_flash_format(content: str) -> List[List[str]]:
    """
    Parse chains from Flash output content (new format only).
    
    Original function: StaticAnalysisAgent._parse_chains
    
    Args:
        content: Flash output content
        
    Returns:
        List of chains, where each chain is a list of gadget strings
    """
    import re
    
    chains = []
    current_chain = []
    
    lines = content.split('\n')
    for line in lines:
        line = line.strip()
        
        if not line:
            if current_chain:
                chains.append(current_chain)
                current_chain = []
            continue
        
        # New format only: [INVOKETYPE] <class:method> --(line:xxx, constraint:xxx)--> <next_class:next_method>
        if re.match(r'\[[A-Z]+\]\s*<[^:]+:\s*[^>]+>\s*--\(line:\d+,\s*constraint:\[[^\]]*\]\)-->\s*<[^:]+:\s*[^>]+>', line):
            current_chain.append(line)
    
    # Add the last chain
    if current_chain:
        chains.append(current_chain)

    return chains


def find_chains_file(project_path: str, flash_dir: str = None) -> str:
    """
    Find chains file automatically based on project path.
    Logic matches run_flash_only.py chains file discovery.
    
    Original function: StaticAnalysisAgent.find_chains_file
    
    Args:
        project_path: Path to the Java project
        flash_dir: Flash directory path
        
    Returns:
        Path to the chains file
    """
    import os
    
    if not flash_dir:
        flash_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "flash")
    
    # Extract project name from project path
    project_name = os.path.basename(project_path.rstrip("/"))
    
    # Priority order for chains file discovery (matching run_flash_only.py):
    # 1. flash/flash_results/{project_name}/chains_{project_name}
    # 2. flash/chains
    # 3. Default "chains" in current directory
    
    candidates = [
        os.path.join(flash_dir, "flash_results", project_name, f"chains_{project_name}"),
        os.path.join(flash_dir, "chains"),
        "chains"
    ]
    
    for candidate in candidates:
        if os.path.exists(candidate):
            print(f"[ChainParser] Found chains file: {candidate}")
            return candidate
    
    # If no chains file found, return the most likely path for error reporting
    print(f"[ChainParser] Warning: No chains file found. Checked:")
    for i, candidate in enumerate(candidates, 1):
        print(f"  {i}. {candidate}")
    return candidates[0]  # Return first candidate for error reporting


def get_chains_file(project_path: str, flash_dir: str = None) -> str:
    """
    Get the path of the chains file generated by Flash

    Original function: StaticAnalysisAgent.get_chains_file

    Args:
        project_path: Java project path
        flash_dir: Flash directory path

    Returns:
        str: Path to the chains file, or None if it does not exist
    """
    import os
    
    chains_file = find_chains_file(project_path, flash_dir)
    
    if os.path.exists(chains_file):
        print(f"[ChainParser] Found chains file: {chains_file}")
        return chains_file
    else:
        print(f"[ChainParser] Chains file not found: {chains_file}")
        return None


def load_chains_file(chains_file: str, project_path: str = None, flash_dir: str = None) -> List[List[str]]:
    """
    Load gadget chains from Flash output file.
    
    Original function: StaticAnalysisAgent.load_chains
    
    Args:
        chains_file: Path to chains file
        project_path: Project path for rediscovery if file not found
        flash_dir: Flash directory path
        
    Returns:
        List of chains, where each chain is a list of gadget strings
    """
    import os
    
    if not os.path.exists(chains_file):
        print(f"[ChainParser] Error: chains file does not exist: {chains_file}")
        
        # If we have project_path, try to find chains file again
        if project_path:
            print(f"[ChainParser] Attempting to rediscover chains file for project: {project_path}")
            rediscovered_file = find_chains_file(project_path, flash_dir)
            if os.path.exists(rediscovered_file):
                chains_file = rediscovered_file
                print(f"[ChainParser] Rediscovered chains file: {chains_file}")
            else:
                return []
        else:
            return []
    
    try:
        with open(chains_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Parse chains from Flash output format
        chains = parse_chains_flash_format(content)
        print(f"[ChainParser] Successfully parsed {len(chains)} gadget chains from {chains_file}")
        return chains
        
    except Exception as e:
        print(f"[ChainParser] Error parsing chains file {chains_file}: {e}")
        return []
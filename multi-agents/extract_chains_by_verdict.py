#!/usr/bin/env python3
"""
Chains processing toolset

Main functions:
1. Extract chains based on CSV verdict
2. Normalize chains format
3. Compare chains overlap

Directly callable functions:
- normalize_chains_file(input_file, output_file): Normalize chains file
- compare_chains_files(file1, file2): Compare overlap of two chains files
- extract_chains_by_verdict(csv_file, chains_file, verdict, output_file): Extract chains based on specified verdict
"""

import argparse
import csv
import os
import re
import sys
from typing import List, Set
from tools.analysis.chain_parser import parse_chains_file


def read_csv_verdicts(csv_file: str, target_verdict: str) -> Set[int]:
    """
    Read chain_id list from CSV file based on specified verdict

    Args:
        csv_file: CSV report file path
        target_verdict: Target verdict (FEASIBLE, NOT_FEASIBLE, NOT_REACHABLE, EARLY_STOP, ERROR)
        
    Returns:
        Set of chain_ids containing the target verdict
    """
    chain_ids = set()
    
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get('verdict', '').upper() == target_verdict.upper():
                    chain_id = int(row.get('chain_id', -1))
                    if chain_id >= 0:
                        chain_ids.add(chain_id)
    except Exception as e:
        print(f"❌ Failed to read CSV file: {e}")
        return set()
    
    return chain_ids


def extract_chains_by_ids(chains_file: str, target_chain_ids: Set[int]) -> List[List[str]]:
    """
    Extract chains from chains file based on specified IDs
    
    Args:
        chains_file: Original chains file path
        target_chain_ids: Set of chain IDs to extract
        
    Returns:
        List of extracted chains
    """
    try:
        all_chains = parse_chains_file(chains_file)
        extracted_chains = []
        
        for chain_id in sorted(target_chain_ids):
            if 0 <= chain_id < len(all_chains):
                extracted_chains.append(all_chains[chain_id])
            else:
                print(f"⚠️ Chain ID {chain_id} out of range (total {len(all_chains)} chains)")
        
        return extracted_chains
    
    except Exception as e:
        print(f"❌ Failed to parse chains file: {e}")
        return []


def normalize_chain_edge(edge: str) -> str:
    """
    Normalize single chain edge
    
    Input example:
    [VIRTUAL] <javax.swing.UIDefaults$TextAndMnemonicHashMap: java.lang.Object get(java.lang.Object)> --(line:1275, constraint:[-1])--> <com.vaadin.data.util.PropertysetItem: java.lang.String toString()>
    
    Output example:
    <javax.swing.UIDefaults$TextAndMnemonicHashMap: java.lang.Object get(java.lang.Object)>->[-1]
    
    Args:
        edge: Original edge string
        
    Returns:
        Normalized edge string
    """
    # Remove call type at the beginning [VIRTUAL], [INTERFACE], [STATIC]
    edge = re.sub(r'^\[(?:VIRTUAL|INTERFACE|STATIC)\]\s*', '', edge.strip())
    
    # Extract caller part (the first < > part)
    caller_match = re.search(r'<[^>]+>', edge)
    if not caller_match:
        return edge  # If caller not found, return original string
    
    caller = caller_match.group(0)
    
    # Extract constraint part
    constraint_match = re.search(r'constraint:\s*(\[[^\]]*\])', edge)
    if constraint_match:
        constraint = constraint_match.group(1)
    else:
        constraint = "[]"  # If constraint not found, use empty array
    
    return f"{caller}->{constraint}"


def normalize_chains(chains: List[List[str]]) -> List[List[str]]:
    """
    Normalize chains list
    
    Args:
        chains: Original chains list
        
    Returns:
        Normalized chains list
    """
    normalized_chains = []
    
    for chain in chains:
        normalized_chain = []
        non_empty_edges = [edge for edge in chain if edge.strip()]  # Filter empty lines
        
        for i, edge in enumerate(non_empty_edges):
            normalized_edge = normalize_chain_edge(edge)
            
            # If it's the last line, remove constraint array
            if i == len(non_empty_edges) - 1:
                # Remove ->[] part, only keep caller
                if '->' in normalized_edge:
                    normalized_edge = normalized_edge.split('->')[0]
            
            normalized_chain.append(normalized_edge)
        
        if normalized_chain:  # Only add non-empty chains
            normalized_chains.append(normalized_chain)
    
    return normalized_chains


def compare_chains_overlap(chains1: List[List[str]], chains2: List[List[str]]) -> dict:
    """
    Compare two chains lists, find overlapping chains
    
    Args:
        chains1: First chains list
        chains2: Second chains list
        
    Returns:
        Dictionary containing overlap information:
        {
            'overlap_count': int,  # Number of overlapping chains
            'overlap_chains': List[tuple],  # Overlapping chains pairs [(index1, index2, chain), ...]
            'total_chains1': int,  # Total number of chains1
            'total_chains2': int,  # Total number of chains2
            'overlap_percentage1': float,  # Overlap percentage in chains1
            'overlap_percentage2': float   # Overlap percentage in chains2
        }
    """
    def chain_to_signature(chain: List[str]) -> str:
        """Convert chain to unique signature string"""
        return '|'.join(sorted(edge.strip() for edge in chain if edge.strip()))
    
    # Create signature to index mapping for chains1
    chains1_signatures = {}
    for i, chain in enumerate(chains1):
        sig = chain_to_signature(chain)
        if sig not in chains1_signatures:
            chains1_signatures[sig] = []
        chains1_signatures[sig].append(i)
    
    # Find overlaps
    overlap_chains = []
    found_signatures = set()
    
    for j, chain2 in enumerate(chains2):
        sig = chain_to_signature(chain2)
        if sig in chains1_signatures and sig not in found_signatures:
            # Find overlaps
            for i in chains1_signatures[sig]:
                overlap_chains.append((i, j, chains1[i]))
            found_signatures.add(sig)
    
    overlap_count = len(found_signatures)
    total_chains1 = len(chains1)
    total_chains2 = len(chains2)
    
    return {
        'overlap_count': overlap_count,
        'overlap_chains': overlap_chains,
        'total_chains1': total_chains1,
        'total_chains2': total_chains2,
        'overlap_percentage1': (overlap_count / total_chains1 * 100) if total_chains1 > 0 else 0,
        'overlap_percentage2': (overlap_count / total_chains2 * 100) if total_chains2 > 0 else 0
    }





def normalize_chains_file(input_file: str, output_file: str) -> bool:
    """
    Normalize chains file
    
    Args:
        input_file: Input chains file path
        output_file: Output normalized chains file path
        
    Returns:
        True if successful, False if failed
    """
    try:
        chains = parse_chains_file(input_file)
        if not chains:
            print(f"❌ Failed to read chains file: {input_file}")
            return False
        
        normalized_chains = normalize_chains(chains)
        save_chains_to_file(normalized_chains, output_file)
        print(f"✅ Normalization completed: {len(normalized_chains)} chains -> {output_file}")
        return True
        
    except Exception as e:
        print(f"❌ Normalization failed: {e}")
        return False


def compare_chains_files(file1: str, file2: str) -> dict:
    """
    Compare overlap of two chains files
    
    Args:
        file1: First chains file path
        file2: Second chains file path
        
    Returns:
        Dictionary containing overlap information
    """
    try:
        chains1 = parse_chains_file(file1)
        chains2 = parse_chains_file(file2)
        
        if not chains1 or not chains2:
            print("❌ Failed to read chains files")
            return {}
        
        # Normalize and compare
        normalized_chains1 = normalize_chains(chains1)
        normalized_chains2 = normalize_chains(chains2)
        
        result = compare_chains_overlap(normalized_chains1, normalized_chains2)
        
        print(f"📊 Overlap analysis result:")
        print(f"  - File1: {result['total_chains1']} chains")
        print(f"  - File2: {result['total_chains2']} chains") 
        print(f"  - Overlap: {result['overlap_count']} chains")
        print(f"  - Overlap percentage: {result['overlap_percentage1']:.1f}% / {result['overlap_percentage2']:.1f}%")
        
        return result
        
    except Exception as e:
        print(f"❌ Comparison failed: {e}")
        return {}


def extract_chains_by_verdict(csv_file: str, chains_file: str, verdict: str, output_file: str = None) -> bool:
    """
    Extract chains based on CSV verdict
    
    Args:
        csv_file: CSV report file path
        chains_file: Original chains file path
        verdict: Verdict type to extract
        output_file: Output file path (optional)
        
    Returns:
        True if successful, False if failed
    """
    try:
        # Read target chain IDs
        target_chain_ids = read_csv_verdicts(csv_file, verdict)
        if not target_chain_ids:
            print(f"❌ No chains found with verdict '{verdict}'")
            return False
        
        # Extract chains
        extracted_chains = extract_chains_by_ids(chains_file, target_chain_ids)
        if not extracted_chains:
            print(f"❌ Failed to extract chains")
            return False
        
        # Set default output file name
        if not output_file:
            csv_dir = os.path.dirname(csv_file)
            chains_basename = os.path.basename(chains_file)
            output_file = os.path.join(csv_dir, f"{chains_basename}_{verdict.lower()}.txt")
        
        # Save chains
        save_chains_to_file(extracted_chains, output_file)
        print(f"✅ Extraction completed: {len(extracted_chains)} chains -> {output_file}")
        return True
        
    except Exception as e:
        print(f"❌ Extraction failed: {e}")
        return False


def save_chains_to_file(chains: List[List[str]], output_file: str=""):
    """
    Save chains to file
    
    Args:
        chains: Chains list
        output_file: Output file path
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for i, chain in enumerate(chains):
                if i > 0:
                    f.write('\n')  # Empty line separates chains
                for edge in chain:
                    f.write(f"{edge}\n")
        
        print(f"✅ Successfully saved {len(chains)} chains to: {output_file}")
    
    except Exception as e:
        print(f"❌ Failed to save file: {e}")


def main():
    """Simplified command line interface"""
    parser = argparse.ArgumentParser(description='Chains processing tool')
    parser.add_argument('--csv', required=True, help='CSV report file path')
    parser.add_argument('--chains', required=True, help='Original chains file path')
    parser.add_argument('--verdict', required=True,
                       choices=['FEASIBLE', 'NOT_FEASIBLE', 'NOT_REACHABLE', 'EARLY_STOP', 'ERROR'],
                       help='Verdict type to extract (FEASIBLE = SAT(Φ(π)), exploitable per paper §3.5)')
    parser.add_argument('--output', help='Output file path')
    
    args = parser.parse_args()
    
    # Use advanced interface function
    success = extract_chains_by_verdict(args.csv, args.chains, args.verdict, args.output)
    
    if not success:
        sys.exit(1)


if __name__ == '__main__':
    main()
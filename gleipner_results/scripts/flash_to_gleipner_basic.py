#!/usr/bin/env python3
"""
Convert Flash chain output to Gleipner evaluator 'basic' format.

Flash format (per edge):
  [DISPATCH] <class: returnType method(params)> --(...)-> <class: returnType method(params)>

Gleipner basic format (per chain):
  className;methodName;arg1;arg2;...
  (blank line separates chains)

Strategy:
  1. Parse each chain's edges to extract all methods
  2. Only keep methods from gleipner.* classes (JDK methods have no annotations)
  3. Deduplicate chains (many Flash chains differ only in JDK entry point)
  4. Convert Java types to JVM-style signatures for the evaluator
"""

import re
import sys
from collections import OrderedDict

# Pattern to match Flash edge format:
# [TYPE] <class: returnType method(params)> --(...)-> <class: returnType method(params)>
EDGE_PATTERN = re.compile(
    r'\[.*?\]\s*<([^>]+)>\s*--\(.*?\)-->\s*<([^>]+)>'
)

# Pattern to parse a method signature: "class: returnType method(params)"
METHOD_PATTERN = re.compile(
    r'([\w.$]+):\s+[\w.$\[\]]+\s+([\w<>]+)\((.*?)\)'
)

# Java type to JVM signature mapping
TYPE_MAP = {
    'int': 'I',
    'long': 'J',
    'short': 'S',
    'byte': 'B',
    'boolean': 'Z',
    'float': 'F',
    'double': 'D',
    'char': 'C',
    'void': 'V',
}


def java_type_to_sig(java_type):
    """Convert a Java type to JVM-like signature for the evaluator."""
    java_type = java_type.strip()
    if not java_type:
        return ''

    # Handle arrays
    array_dims = 0
    while java_type.endswith('[]'):
        array_dims += 1
        java_type = java_type[:-2]

    prefix = '[' * array_dims

    if java_type in TYPE_MAP:
        return prefix + TYPE_MAP[java_type]
    else:
        # Object type: L prefix
        return prefix + 'L' + java_type


def parse_method(sig):
    """Parse 'class: returnType method(params)' into (class, method, [arg_sigs])."""
    m = METHOD_PATTERN.match(sig.strip())
    if not m:
        return None
    class_name = m.group(1)
    method_name = m.group(2)
    params_str = m.group(3).strip()

    if params_str:
        params = [p.strip() for p in params_str.split(',')]
        arg_sigs = [java_type_to_sig(p) for p in params]
    else:
        arg_sigs = []

    return class_name, method_name, arg_sigs


def parse_flash_chains(filepath):
    """Parse Flash chain output file into list of chains.
    Each chain is a list of (class, method, [arg_sigs]) tuples."""
    chains = []
    current_chain = []

    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line:
                if current_chain:
                    chains.append(current_chain)
                    current_chain = []
                continue

            m = EDGE_PATTERN.match(line)
            if not m:
                continue

            src_sig = m.group(1)
            dst_sig = m.group(2)

            src = parse_method(src_sig)
            dst = parse_method(dst_sig)

            if src:
                current_chain.append(src)
            if dst:
                current_chain.append(dst)

    if current_chain:
        chains.append(current_chain)

    return chains


def filter_gleipner_methods(chain):
    """Keep only methods from gleipner.* classes."""
    seen = set()
    filtered = []
    for class_name, method_name, arg_sigs in chain:
        if not class_name.startswith('gleipner.'):
            continue
        key = (class_name, method_name, tuple(arg_sigs))
        if key not in seen:
            seen.add(key)
            filtered.append((class_name, method_name, arg_sigs))
    return filtered


def chain_to_key(chain):
    """Create a hashable key for deduplication."""
    return tuple((c, m, tuple(a)) for c, m, a in chain)


def chain_to_basic(chain):
    """Convert a chain to basic format lines."""
    lines = []
    for class_name, method_name, arg_sigs in chain:
        parts = [class_name, method_name] + arg_sigs
        lines.append(';'.join(parts))
    return lines


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <flash_chains_file> [output_file]")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None

    # Parse Flash chains
    raw_chains = parse_flash_chains(input_file)
    print(f"Parsed {len(raw_chains)} raw chains from Flash output")

    # Filter to gleipner classes only
    filtered_chains = []
    for chain in raw_chains:
        filtered = filter_gleipner_methods(chain)
        if filtered:
            filtered_chains.append(filtered)

    print(f"  {len(filtered_chains)} chains contain gleipner.* classes")

    # Deduplicate
    seen = OrderedDict()
    for chain in filtered_chains:
        key = chain_to_key(chain)
        if key not in seen:
            seen[key] = chain

    unique_chains = list(seen.values())
    print(f"  {len(unique_chains)} unique chains after deduplication")

    # Output
    output_lines = []
    for chain in unique_chains:
        basic_lines = chain_to_basic(chain)
        output_lines.extend(basic_lines)
        output_lines.append('')  # blank line separator

    output_text = '\n'.join(output_lines)

    if output_file:
        with open(output_file, 'w') as f:
            f.write(output_text)
        print(f"Written to {output_file}")
    else:
        print(output_text)


if __name__ == '__main__':
    main()

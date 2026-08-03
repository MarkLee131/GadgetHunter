#!/usr/bin/env python3
"""
Flash-only runner: invoke the Flash JAR (Phase A taint analysis) without the
multi-agent LLM stack.

Path resolution rules
---------------------
- config.yml   : --config > <project_path>/config.yml
- output_dir   : --output_dir > config.yml `outputDir` > 'flash_results'
                 (created on demand)
- flash_dir    : multi-agents/flash/ (where flash.jar lives)
- chains_file  : --chains_file > <output_dir>/<project_name>/chains_<project_name>
                 > first chains_* file under <output_dir>
- log_file     : --log_file > <project_path>/log.log
- Other params : CLI > config.yml > built-in defaults

Parameter precedence: CLI > config.yml > defaults.

Usage:
    python run_flash_only.py --project_path /path/to/project \
                             --output_dir   /path/to/output \
                             --flash_jar    flash.jar \
                             --config       /path/to/config.yml
"""

import argparse
import os
import json
import sys
import shutil
from pathlib import Path
import yaml

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from runners.flash_runner import FlashRunner

def load_config(config_path):
    if config_path and os.path.exists(config_path):
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        print(f"[FlashOnly] Loaded config from {config_path}")
        return config
    else:
        print(f"[FlashOnly] Warning: Config file {config_path} not found, using empty config.")
        return {}

def merge_config_with_args(config, args):
    # Script parameters take precedence over config.yml
    merged = dict(config)
    arg_map = {
        'output_dir': args.output_dir,
        'project_path': args.project_path,
        'flash_jar': args.flash_jar,
        'java_opts': args.java_opts,
        'log_file': args.log_file,
    }
    for k, v in arg_map.items():
        if v:
            merged[k] = v
    # outputDir field synchronization
    if 'output_dir' in merged:
        merged['outputDir'] = merged['output_dir']
    return merged

def find_chains_file(output_dir, project_name=None, user_chains_file=None):
    # Use user specified first
    if user_chains_file and os.path.exists(user_chains_file):
        return user_chains_file
    # Then find output_dir/flash_results/{project_name}/chains_{project_name}
    if project_name:
        candidate = os.path.join(output_dir, project_name, f"chains_{project_name}")
        if os.path.exists(candidate):
            return candidate
    # Then find all chains_* files in output_dir
    if os.path.exists(output_dir):
        for fname in os.listdir(output_dir):
            if fname.startswith("chains_"):
                candidate = os.path.join(output_dir, fname)
                if os.path.exists(candidate):
                    return candidate
    return None

def main():
    parser = argparse.ArgumentParser(
        description="Run Flash tool without LLM analysis (robust config/arg merging)"
    )
    parser.add_argument('--flash_jar', default='flash.jar', help='Path to Flash JAR file, relative to multi-agents/flash/ (default: flash.jar)')
    parser.add_argument('--config', dest='config_path', help='Path to config.yml (default: project_path/config.yml)')
    parser.add_argument('--project_path', help='Project path (will use project_path/config.yml if --config not specified)')
    parser.add_argument('--output_dir', default='flash_results', help='Output directory for results')
    parser.add_argument('--java_opts', default='-Xss1024m -Xmx16G', help='Java options (default: -Xss1024m -Xmx8G)')
    parser.add_argument('--log_file', help='Log file path (default: project_path/log.log if project_path specified)')
    parser.add_argument('--chains_file', help='Path to chains file (optional, will auto-detect if not specified)')
    parser.add_argument('--analyze_only', action='store_true', help='Only analyze existing chains file, do not run Flash')
    parser.add_argument('--copy_time_file', action='store_true', help='Copy `time` file to output directory after execution')
    args = parser.parse_args()

    # 1. Parse config path
    config_path = args.config_path
    if not config_path and args.project_path:
        config_path = os.path.join(args.project_path, "config.yml")
    config = load_config(config_path)

    # 2. Merge parameters
    merged = merge_config_with_args(config, args)
    output_dir = merged.get('output_dir', 'flash_results')
    project_path = merged.get('project_path', None)
    flash_jar = merged.get('flash_jar', 'flash.jar')
    java_opts = merged.get('java_opts', '-Xss1024m -Xmx16G')
    log_file = merged.get('log_file', None)
    if not log_file and project_path:
        log_file = os.path.join(project_path, "log.log")

    # 3. Locate the Flash working dir (multi-agents/flash/) and ensure output dir exists
    flash_dir = os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "flash")
    )
    os.makedirs(output_dir, exist_ok=True)

    # 4. Run Flash tool
    results = {
        "flash_config": {
            "flash_jar": flash_jar,
            "flash_config": config_path,
            "project_path": project_path,
            "java_opts": java_opts,
            "flash_directory": flash_dir
        },
        "flash_results": [],
        "summary": {}
    }
    if not args.analyze_only:
        print("[FlashOnly] Step 1: Running Flash tool...")
        print(f"[FlashOnly] Flash directory: {flash_dir}")
        try:
            runner = FlashRunner(
                jar_path=flash_jar,
                config_path=config_path,
                java_opts=java_opts,
                project_path=project_path if project_path else "",
                log_file=log_file if log_file else ""
            )
            flash_results = runner.run()
            results["flash_results"] = flash_results
            print(f"[FlashOnly] Flash completed. Found {len(flash_results)} results")
            # Automatically copy time file to output_dir/{project_name}/time_{project_name}
            if project_path:
                project_name = os.path.basename(project_path.rstrip("/"))
                src_time = os.path.join(flash_dir, "time")
                dst_dir = os.path.join(output_dir, project_name)
                dst_time = os.path.join(dst_dir, f"time_{project_name}")
                if os.path.exists(src_time):
                    os.makedirs(dst_dir, exist_ok=True)
                    shutil.copy2(src_time, dst_time)
                    print(f"[FlashOnly] Time file copied to {dst_time}")
                else:
                    print(f"[FlashOnly] Warning: Time file {src_time} not found")
        except Exception as e:
            print(f"[FlashOnly] Error running Flash: {e}")
            return 1

    # 5. Find chains file
    project_name = os.path.basename(project_path.rstrip("/")) if project_path else None
    chains_file = find_chains_file(output_dir, project_name, args.chains_file)
    if chains_file and os.path.exists(chains_file):
        print(f"[FlashOnly] Chains file generated: {chains_file}")
    else:
        print(f"[FlashOnly] Warning: No chains file found! Checked:")
        if project_name:
            print(f"  1. {os.path.join(output_dir, project_name, f'chains_{project_name}')}")
        print(f"  2. {output_dir}/chains_* (all chains files in output_dir)")
        if not args.analyze_only:
            print("[FlashOnly] Flash may have failed to generate chains file")

    # 6. Save results
    if project_name:
        results_file = os.path.join(output_dir, project_name, "flash_only_results.json")
        os.makedirs(os.path.join(output_dir, project_name), exist_ok=True)
    else:
        results_file = os.path.join(output_dir, "flash_only_results.json")
    try:
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"[FlashOnly] Complete results saved to {results_file}")
    except Exception as e:
        print(f"[FlashOnly] Error saving results: {e}")

    print("[FlashOnly] Flash-only execution completed!")
    return 0

if __name__ == "__main__":
    sys.exit(main()) 
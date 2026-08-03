"""
Flash tool runner module.
"""

import os
import json
import subprocess
from typing import List, Dict, Any
from pathlib import Path


class FlashRunner:
    """Runner for Flash tool."""
    
    def __init__(self, jar_path: str, config_path: str, java_opts: str = "-Xss1024m -Xmx8G", project_path: str = None, log_file: str = None, time_file: str = None):
        # Flash working directory: multi-agents/flash/  (sibling of tools/, where flash.jar lives)
        self.flash_dir = os.path.normpath(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "flash")
        )

        # Paths are resolved relative to flash_dir; absolute paths get rebased.
        self.jar_path = os.path.relpath(jar_path, self.flash_dir) if os.path.isabs(jar_path) else jar_path
        self.config_path = os.path.relpath(config_path, self.flash_dir) if os.path.isabs(config_path) else config_path

        self.java_opts = java_opts
        self.project_path = project_path
        self.log_file = log_file
        self.time_file = time_file
    
    def run(self) -> List[Dict[str, Any]]:
        """Run Flash tool and return results."""
        # Check if jar_path exists relative to flash directory
        jar_abs_path = os.path.join(self.flash_dir, self.jar_path)
        if not os.path.exists(jar_abs_path):
            raise FileNotFoundError(f"Flash JAR file does not exist: {jar_abs_path}")
        
        # Check if config_path exists relative to flash directory
        config_abs_path = os.path.join(self.flash_dir, self.config_path)
        if not os.path.exists(config_abs_path):
            raise FileNotFoundError(f"Flash config file does not exist: {config_abs_path}")
        
        # Build Java command exactly like shell script

        if isinstance(self.java_opts, str):
            java_opts = self.java_opts.split()
        else:
            java_opts = self.java_opts

        cmd = [
            "java",
            *java_opts,
            "-jar", self.jar_path,
            "--options-file", self.config_path
        ]
        
        print(f"Running Flash command: {' '.join(cmd)}")
        print(f"Working directory: {self.flash_dir}")

        try:
            # Run Flash tool in flash directory
            if self.log_file:
                log_abs_path = os.path.join(self.flash_dir, self.log_file)
                os.makedirs(os.path.dirname(log_abs_path), exist_ok=True)
                with open(log_abs_path, "w", encoding="utf-8") as logf:
                    result = subprocess.run(cmd, stdout=logf, stderr=subprocess.STDOUT, cwd=self.flash_dir)
            else:
                result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.flash_dir)
            
            if result.returncode != 0:
                print(f"Flash execution failed, return code: {result.returncode}")
                if not self.log_file:
                    print(f"Error output: {result.stderr}")
                return []
            
            print("Flash executed successfully")
            if not self.log_file:
                print(f"Standard output: {result.stdout}")
            
            # Parse results from flash directory
            return self._parse_results()
            
        except Exception as e:
            print(f"Error running Flash: {e}")
            return []
    
    def _parse_results(self) -> List[Dict[str, Any]]:
        """Parse Flash results from output files."""
        results = []
        # Automatically find chains file
        candidate_files = []
        project_name = None
        if hasattr(self, 'project_path') and self.project_path and isinstance(self.project_path, str):
            project_name = os.path.basename(self.project_path.rstrip("/"))
            if project_name:
                candidate_files.append(os.path.join(self.flash_dir, "flash_results", project_name, f"chains_{project_name}"))
        candidate_files.append(os.path.join(self.flash_dir, "chains"))
        for file_path in candidate_files:
            if file_path and os.path.exists(file_path):
                try:
                    if file_path.endswith('.json'):
                        with open(file_path, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            if isinstance(data, list):
                                results.extend(data)
                            else:
                                results.append(data)
                    else:
                        # Parse plain text chains file
                        chains = self._parse_chains_file(file_path)
                        results.extend(chains)
                    print(f"Parsed {len(results)} results from {file_path}")
                    break
                except Exception as e:
                    print(f"Error parsing {file_path}: {e}")
                    continue
        return results
    
    def _parse_chains_file(self, filename: str) -> List[Dict[str, Any]]:
        """Parse plain text chains file."""
        chains = []
        current_chain = []
        chain_id = 0
        
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        if current_chain:
                            chains.append({
                                "id": chain_id,
                                "name": f"Chain_{chain_id}",
                                "chain": current_chain.copy(),
                                "source": filename
                            })
                            chain_id += 1
                            current_chain = []
                    else:
                        current_chain.append(line)
            
            # Add the last chain if exists
            if current_chain:
                chains.append({
                    "id": chain_id,
                    "name": f"Chain_{chain_id}",
                    "chain": current_chain,
                    "source": filename
                })
        
        except Exception as e:
            print(f"Error parsing chains file: {e}")
        
        return chains 


def run_flash_wrapper(project_path: str, flash_config: str = None, java_opts: str = "-Xss1024m -Xmx8G") -> bool:
    """
    Run Flash tool to scan Java project
    
    Original function: StaticAnalysisAgent.run_flash
    
    Args:
        project_path: Java project path
        flash_config: Flash config file path (optional)
        java_opts: Java runtime options
        
    Returns:
        bool: Whether Flash successfully ran
    """
    import os
    
    # Determine config file path
    if not flash_config:
        flash_config = os.path.join(project_path, "config.yml")
    
    # Create FlashRunner
    runner = FlashRunner(
        jar_path="flash.jar",
        config_path=flash_config,
        java_opts=java_opts,
        project_path=project_path
    )
    
    # Run Flash
    print(f"[FlashRunner] Running Flash on project: {project_path}")
    results = runner.run()
    
    if results:
        print(f"[FlashRunner] Flash completed successfully")
        return True
    else:
        print(f"[FlashRunner] Flash failed")
        return False 
"""
Z3 Script Manager
View and manage saved Z3 scripts for debugging
"""

import os
import glob
import subprocess
from typing import Dict, List
from datetime import datetime


class Z3ScriptManager:
    """Manage saved Z3 scripts for debugging."""
    
    def __init__(self, scripts_dir: str = "z3_scripts"):
        self.scripts_dir = scripts_dir
    
    def list_run_sessions(self) -> List[str]:
        """List all run sessions with Z3 scripts."""
        if not os.path.exists(self.scripts_dir):
            return []
        
        sessions = []
        for item in os.listdir(self.scripts_dir):
            item_path = os.path.join(self.scripts_dir, item)
            if os.path.isdir(item_path):
                sessions.append(item)
        
        return sorted(sessions, reverse=True)  # Most recent first
    
    def list_scripts_in_session(self, session_id: str) -> List[Dict[str, any]]:
        """List all Z3 scripts in a run session."""
        session_path = os.path.join(self.scripts_dir, session_id)
        if not os.path.exists(session_path):
            return []
        
        scripts = []
        for file_path in glob.glob(os.path.join(session_path, "*.py")):
            filename = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            mod_time = datetime.fromtimestamp(os.path.getmtime(file_path))
            
            # Parse script info from filename
            script_info = self._parse_script_filename(filename)
            
            script_data = {
                "filename": filename,
                "file_path": file_path,
                "size_bytes": file_size,
                "size_mb": round(file_size / (1024 * 1024), 2),
                "modified": mod_time.strftime("%Y-%m-%d %H:%M:%S"),
                **script_info
            }
            
            scripts.append(script_data)
        
        return sorted(scripts, key=lambda x: x["timestamp"])
    
    def _parse_script_filename(self, filename: str) -> Dict[str, any]:
        """Parse script information from filename."""
        # Expected format: chain_{chain_id}_{script_type}_{timestamp}.py
        parts = filename.replace('.py', '').split('_')
        
        if len(parts) >= 4 and parts[0] == 'chain':
            try:
                chain_id = int(parts[1])
                script_type = parts[2]
                timestamp = int(parts[3])
                
                return {
                    "chain_id": chain_id,
                    "script_type": script_type,
                    "timestamp": timestamp,
                    "parsed": True
                }
            except (ValueError, IndexError):
                pass
        
        return {
            "chain_id": -1,
            "script_type": "unknown",
            "timestamp": 0,
            "parsed": False
        }
    
    def read_script_content(self, file_path: str, max_lines: int = 100) -> Dict[str, any]:
        """Read Z3 script content with preview."""
        if not os.path.exists(file_path):
            return {"error": "File not found"}
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            lines = content.split('\n')
            preview_lines = lines[:max_lines]
            has_more = len(lines) > max_lines
            
            return {
                "content": content,
                "preview": '\n'.join(preview_lines),
                "total_lines": len(lines),
                "preview_lines": len(preview_lines),
                "has_more": has_more,
                "file_size_mb": round(os.path.getsize(file_path) / (1024 * 1024), 2)
            }
            
        except Exception as e:
            return {"error": f"Error reading file: {str(e)}"}
    
    def execute_script(self, file_path: str) -> Dict[str, any]:
        """Execute a Z3 script and return results."""
        if not os.path.exists(file_path):
            return {"error": "File not found"}
        
        try:
            # Execute script
            result = subprocess.run(
                ['python', file_path], 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode,
                "error": result.stderr if result.returncode != 0 else None
            }
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Execution timed out (30s)"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_session_summary(self, session_id: str) -> Dict[str, any]:
        """Get summary of Z3 scripts in a session."""
        scripts = self.list_scripts_in_session(session_id)
        
        if not scripts:
            return {"error": "No scripts found"}
        
        summary = {
            "session_id": session_id,
            "total_scripts": len(scripts),
            "total_size_mb": sum(s["size_mb"] for s in scripts),
            "chains": {},
            "script_types": {}
        }
        
        # Group by chain
        for script in scripts:
            chain_id = script["chain_id"]
            script_type = script["script_type"]
            
            if chain_id not in summary["chains"]:
                summary["chains"][chain_id] = []
            summary["chains"][chain_id].append(script)
            
            if script_type not in summary["script_types"]:
                summary["script_types"][script_type] = 0
            summary["script_types"][script_type] += 1
        
        return summary
    
    def print_session_summary(self, session_id: str):
        """Print a formatted summary of Z3 scripts in a session."""
        summary = self.get_session_summary(session_id)
        
        if "error" in summary:
            print(f"❌ {summary['error']}")
            return
        
        print(f"\n🔧 Z3 Scripts Summary: {session_id}")
        print("=" * 50)
        print(f"Total Scripts: {summary['total_scripts']}")
        print(f"Total Size: {summary['total_size_mb']} MB")
        print()
        
        print("📁 Chains:")
        for chain_id, scripts in summary["chains"].items():
            print(f"  🔗 Chain {chain_id}: {len(scripts)} scripts")
            for script in scripts:
                print(f"    📄 {script['filename']} ({script['script_type']})")
            print()
        
        print("📊 Script Types:")
        for script_type, count in summary["script_types"].items():
            print(f"  🗂️  {script_type}: {count}")
        print()
    
    def print_scripts_list(self, session_id: str):
        """Print formatted list of scripts in a session."""
        scripts = self.list_scripts_in_session(session_id)
        
        if not scripts:
            print(f"❌ No Z3 scripts found in session '{session_id}'")
            return
        
        print(f"\n📋 Z3 Scripts: {session_id}")
        print("=" * 50)
        
        for script in scripts:
            print(f"📄 {script['filename']}")
            print(f"   Chain: {script['chain_id']}")
            print(f"   Type: {script['script_type']}")
            print(f"   Size: {script['size_mb']} MB")
            print(f"   Modified: {script['modified']}")
            print()


def main():
    """Command-line interface for Z3 script management."""
    import sys
    
    script_manager = Z3ScriptManager()
    
    if len(sys.argv) < 2:
        print("Usage: python z3_script_manager.py <command> [args]")
        print("\nCommands:")
        print("  list-sessions                    - List all run sessions with Z3 scripts")
        print("  summary <session_id>             - Show session summary")
        print("  scripts <session_id>             - List scripts in session")
        print("  read <file_path> [max_lines]     - Read script content")
        print("  execute <file_path>              - Execute Z3 script")
        return
    
    command = sys.argv[1]
    
    if command == "list-sessions":
        sessions = script_manager.list_run_sessions()
        if sessions:
            print("📁 Z3 Script Sessions:")
            for session in sessions:
                print(f"  {session}")
        else:
            print("❌ No Z3 script sessions found")
    
    elif command == "summary" and len(sys.argv) >= 3:
        session_id = sys.argv[2]
        script_manager.print_session_summary(session_id)
    
    elif command == "scripts" and len(sys.argv) >= 3:
        session_id = sys.argv[2]
        script_manager.print_scripts_list(session_id)
    
    elif command == "read" and len(sys.argv) >= 3:
        file_path = sys.argv[2]
        max_lines = int(sys.argv[3]) if len(sys.argv) >= 4 else 100
        content = script_manager.read_script_content(file_path, max_lines)
        
        if "error" in content:
            print(f"❌ {content['error']}")
        else:
            print(f"📄 {file_path}")
            print(f"Size: {content['file_size_mb']} MB")
            print(f"Lines: {content['total_lines']}")
            print("=" * 50)
            print(content["preview"])
            if content["has_more"]:
                print(f"\n... (showing {content['preview_lines']} of {content['total_lines']} lines)")
    
    elif command == "execute" and len(sys.argv) >= 3:
        file_path = sys.argv[2]
        result = script_manager.execute_script(file_path)
        
        if result["success"]:
            print(f"✅ Script executed successfully")
            print("Output:")
            print(result["stdout"])
        else:
            print(f"❌ Script execution failed")
            print(f"Error: {result['error']}")
            if result["stderr"]:
                print("Stderr:")
                print(result["stderr"])
    
    else:
        print("❌ Invalid command or missing arguments")
        print("Use 'python z3_script_manager.py' for help")


if __name__ == "__main__":
    main() 
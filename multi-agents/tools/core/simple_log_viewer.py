"""
Minimal log management for LLM interactions
Provide basic log viewing and searching functionality, no complex formatting
"""

import os
import glob
from typing import List, Dict


class SimpleLogViewer:
    """Minimal log viewer - only provides core functionality"""
    
    def __init__(self, results_dir: str = "results"):
        self.results_dir = results_dir
    
    def list_sessions(self) -> List[str]:
        """List all session directories"""
        if not os.path.exists(self.results_dir):
            return []
        
        sessions = []
        for item in os.listdir(self.results_dir):
            item_path = os.path.join(self.results_dir, item)
            if os.path.isdir(item_path) and not item.startswith('.'):
                sessions.append(item)
        
        return sorted(sessions, reverse=True)  # The latest ones are at the front
    
    def list_files_in_session(self, session: str) -> List[str]:
        """List all log files in the session"""
        session_path = os.path.join(self.results_dir, session)
        if not os.path.exists(session_path):
            return []
        
        # Find all .txt files (LLM logs)
        pattern = os.path.join(session_path, "**", "*.txt")
        files = glob.glob(pattern, recursive=True)
        
        # Return relative paths, for display convenience
        relative_files = [os.path.relpath(f, session_path) for f in files]
        return sorted(relative_files)
    
    def search_logs(self, session: str, search_term: str, case_sensitive: bool = False) -> List[Dict[str, str]]:
        """Search for content across all logs of a session"""
        session_path = os.path.join(self.results_dir, session)
        if not os.path.exists(session_path):
            return []
        
        results = []
        search_term_processed = search_term if case_sensitive else search_term.lower()
        
        pattern = os.path.join(session_path, "**", "*.txt")
        for file_path in glob.glob(pattern, recursive=True):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                content_processed = content if case_sensitive else content.lower()
                if search_term_processed in content_processed:
                    relative_path = os.path.relpath(file_path, session_path)
                    match_count = content_processed.count(search_term_processed)
                    results.append({
                        "file": relative_path,
                        "path": file_path,
                        "matches": match_count
                    })
            except Exception:
                continue
        
        return sorted(results, key=lambda x: x["matches"], reverse=True)
    
    def read_file(self, session: str, file_path: str, max_lines: int = None) -> str:
        """Read the specified log file"""
        if not file_path.startswith('/'):
            # Relative path, concatenate session path
            full_path = os.path.join(self.results_dir, session, file_path)
        else:
            full_path = file_path
        
        if not os.path.exists(full_path):
            return f"❌ File does not exist: {full_path}"
        
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            if max_lines:
                lines = content.split('\n')
                if len(lines) > max_lines:
                    content = '\n'.join(lines[:max_lines])
                    content += f"\n\n... (Display the first {max_lines} lines, total {len(lines)} lines)"
            
            return content
        except Exception as e:
            return f"❌ Error reading file: {e}"


def main():
    """Command line interface"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python simple_log_viewer.py <command> [parameters]")
        print("Commands:")
        print("  sessions                     - List all sessions")
        print("  files <session>              - List all files in the session")
        print("  search <session> <keyword>     - Search log content")
        print("  read <session> <file path>     - Read log file")
        return
    
    viewer = SimpleLogViewer()
    command = sys.argv[1]
    
    if command == "sessions":
        sessions = viewer.list_sessions()
        if sessions:
            print("📁 Available sessions:")
            for session in sessions:
                print(f"  {session}")
        else:
            print("❌ No sessions found")
    
    elif command == "files" and len(sys.argv) >= 3:
        session = sys.argv[2]
        files = viewer.list_files_in_session(session)
        if files:
            print(f"📄 Log files in {session}:")
            for file in files:
                print(f"  {file}")
        else:
            print(f"❌ No log files found in {session}")
    
    elif command == "search" and len(sys.argv) >= 4:
        session = sys.argv[2]
        term = sys.argv[3]
        results = viewer.search_logs(session, term)
        if results:
            print(f"🔍 Results in {session} for '{term}':")
            for result in results:
                print(f"  📄 {result['file']} ({result['matches']} matches)")
        else:
            print(f"❌ No matches found for '{term}'")
    
    elif command == "read" and len(sys.argv) >= 4:
        session = sys.argv[2]
        file_path = sys.argv[3]
        max_lines = int(sys.argv[4]) if len(sys.argv) >= 5 else None
        content = viewer.read_file(session, file_path, max_lines)
        print(content)
    
    else:
        print("❌ Invalid command or missing parameters")


if __name__ == "__main__":
    main()

import os
import subprocess
from pathlib import Path
from typing import Optional

def run_flash_batch(
    root_dir: str,
    flash_jar: str = "flash.jar",
    java_opts: str = "-Xss1024m -Xmx8G",
    time_file: Optional[str] = None
):
    """
    Batch run Flash tool for each subproject in root_dir.
    :param root_dir: Root directory, each subdirectory is a project to analyze
    :param flash_jar: Path to Flash tool jar
    :param java_opts: Java options
    :param time_file: Optional, path to time file to copy after analysis
    """
    root = Path(root_dir)
    if not root.exists():
        print(f"Root directory does not exist: {root_dir}")
        return

    for subdir in root.iterdir():
        if subdir.is_dir():
            target_name = subdir.name
            config_file = subdir / "config.yml"
            log_file = subdir / "log.log"
            if not config_file.exists():
                print(f"Skip: {config_file} does not exist")
                continue
            print(f"Analyzing: {target_name}")
            cmd = [
                "java",
                *java_opts.split(),
                "-jar", flash_jar,
                "--options-file", str(config_file)
            ]
            with open(log_file, "w") as logf:
                result = subprocess.run(cmd, stdout=logf, stderr=subprocess.STDOUT)
            if result.returncode == 0:
                print(f"  Done: {target_name}")
            else:
                print(f"  Failed: {target_name}, check log {log_file}")
            # Optionally copy time file
            if time_file and os.path.exists(time_file):
                dest_time = subdir / "time"
                subprocess.run(["cp", time_file, str(dest_time)]) 
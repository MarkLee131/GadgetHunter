# Flash-Only Usage Guide

This guide explains how to run Flash tool without LLM analysis.

## Important: Path Handling

**All path parameters (flash_jar, config, project_path, output_dir, chains_file, log_file) can be absolute paths or paths relative to the `multi-agents/` directory!**

- Flash tool runs in the `multi-agents/flash` directory by default
- All input/output paths can be absolute or relative to multi-agents/
- Do not use `./` prefix - use relative paths directly or absolute paths
- Output files (chains, logs, results) are generated in the specified output directory

## Parameter Precedence

> **Parameter precedence:** Command line arguments > config.yml > script default values
> For example, if both `--output_dir` and `outputDir` in config.yml are set, the command line argument takes precedence.

## Quick Start

### 1. Run Flash Tool Only

```bash
# Basic usage - run Flash and analyze results
python run_flash_only.py --flash_jar flash.jar --project_path java-benchmarks/JDV/target/BeanShell

# Only analyze an existing chains file
python run_flash_only.py --flash_jar flash.jar --analyze_only
```

### 2. Command Line Options

| Option           | Description                        | Required | Default         | Path Type                        |
|------------------|------------------------------------|----------|-----------------|----------------------------------|
| `--flash_jar`    | Path to Flash JAR file             | Yes      | -               | Absolute or relative to multi-agents |
| `--config`       | Path to config.yml                 | No       | project_path/config.yml | Absolute or relative to multi-agents |
| `--project_path` | Project path                       | No       | -               | Absolute or relative to multi-agents |
| `--output_dir`   | Output directory                   | No       | flash_results   | Absolute or relative to multi-agents |
| `--chains_file`  | Path to chains file                | No       | auto-detect     | Absolute or relative to output_dir   |
| `--log_file`     | Log file path                      | No       | project_path/log.log | Absolute or relative to multi-agents |
| `--java_opts`    | Java options                       | No       | -Xss1024m -Xmx16G | -                              |
| `--analyze_only` | Only analyze existing chains       | No       | False           | -                                |
| `--copy_time_file`| Copy time file to output dir      | No       | False           | -                                |

### 3. Parameter Resolution and Path Search

- `--config` takes precedence for config file; if not set, uses `--project_path/config.yml`.
- `--output_dir` takes precedence for output directory; if not set, uses `outputDir` in config.yml, else defaults to `flash_results`.
- `--chains_file` takes precedence for chains file; if not set, auto-searches:
    1. `{output_dir}/{project_name}/chains_{project_name}`
    2. Any `chains_*` file in `{output_dir}`
- All paths can be absolute or relative to multi-agents/.

### 4. Examples

#### Example 1: Run Flash on a Java project
```bash
python run_flash_only.py \
  --flash_jar flash.jar \
  --project_path java-benchmarks/JDV/target/BeanShell \
  --output_dir my_results
```

#### Example 2: Analyze existing chains file
```bash
python run_flash_only.py \
  --flash_jar flash.jar \
  --analyze_only \
  --output_dir analysis_results
```

#### Example 3: Specify config and chains file
```bash
python run_flash_only.py \
  --flash_jar flash.jar \
  --config my_project/config.yml \
  --chains_file my_results/chains_my_project
```

#### Example 4: Use absolute paths
```bash
python run_flash_only.py \
  --flash_jar /abs/path/to/flash.jar \
  --project_path /abs/path/to/project \
  --output_dir /abs/path/to/output
```

## Directory Structure

### Expected Structure
```
multi-agents/
├── flash/                          # Flash working directory
│   ├── flash.jar                   # Flash JAR file
│   ├── java-benchmarks/            # Example project
│   │   └── JDV/
│   │       └── target/
│   │           └── BeanShell/
│   │               ├── config.yml  # Flash config
│   │               └── classes/    # Compiled classes
│   ├── chains                      # (optional) Generated chains file
│   └── flash.log                   # (optional) Flash execution log
├── run_flash_only.py               # This script
└── flash_results/                  # Output directory (default or custom)
    ├── flash_analysis.json
    ├── flash_summary.md
    └── flash_only_results.json
```

### Flash Configuration File
Your project should have a `config.yml` file in the project directory:

```yaml
# Example config.yml (relative to multi-agents or absolute)
input: java-benchmarks/JDV/target/BeanShell/classes
output-dir: output
main-class: com.example.MainClass
world-builder: pascal.taie.frontend.soot.SootWorldBuilder
```

## Path Examples

### Correct Path Usage

| File Type | Example Path | Description |
|-----------|--------------|-------------|
| Flash JAR | `flash.jar` or `/abs/path/to/flash.jar` | JAR file in flash directory or absolute |
| Project   | `java-benchmarks/JDV/target/BeanShell` or `/abs/path/to/project` | Project path |
| Config    | `java-benchmarks/JDV/target/BeanShell/config.yml` or `/abs/path/to/config.yml` | Config file |
| Log       | `java-benchmarks/JDV/target/BeanShell/flash.log` or `/abs/path/to/log.log` | Log file |
| Output    | `flash_results` or `/abs/path/to/output` | Output directory |
| Chains    | `flash_results/chains_my_project` or `/abs/path/to/chains_file` | Chains file |

### Incorrect Path Usage

| Incorrect Path | Issue |
|----------------|-------|
| `./flash.jar` | Don't use `./` prefix |
| `../flash.jar` | Don't go outside multi-agents directory |
| `flash/flash.jar` | Don't include flash/ prefix |

## Output Files

The script generates the following output files in the specified output directory:

### 1. `flash_analysis.json`
Contains detailed analysis of the gadget chains (if analysis is enabled):
- Chain statistics
- Complexity analysis
- Method and class information
- Chain details

### 2. `flash_summary.md`
Human-readable summary report (if analysis is enabled):
- Total chains found
- Average complexity
- Distribution statistics
- Key findings

### 3. `flash_only_results.json`
Complete results including:
- Flash configuration used
- Raw Flash results
- (If analysis enabled) Analysis results
- (If analysis enabled) Summary statistics

## Troubleshooting

### Common Issues

1. **Flash JAR not found**
   ```
   Error: Flash JAR file does not exist: /path/to/flash/flash.jar
   ```
   Solution: Check that the JAR file exists in the specified location

2. **Config file not found**
   ```
   Error: Flash config file does not exist: /path/to/flash/config.yml
   ```
   Solution: Ensure config.yml exists in your project directory (absolute or relative to multi-agents)

3. **Java execution failed**
   ```
   Flash execution failed, return code: 1
   ```
   Solution: Check the log file for detailed error messages

4. **No chains file generated**
   ```
   Warning: Chains file '/path/to/output/chains_my_project' not found
   ```
   Solution: Flash may have failed to generate chains. Check the log file.

### Debug Mode

To get more detailed output, you can modify the script to add debug logging:

```python
# Add to run_flash_only.py
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Integration with Multi-Agent Framework

The Flash-only script is designed to work independently but can also be integrated with the full multi-agent framework:

1. **Run Flash-only first** to generate chains
2. **Use the chains file** with the full framework for LLM analysis
3. **Compare results** between Flash-only and LLM-enhanced analysis

```bash
# Step 1: Run Flash-only
python run_flash_only.py --flash_jar flash.jar --project_path my_project

# Step 2: Run full analysis with LLM
python main.py --skip_flash --use_enhanced --openai_key your_key
```

## Performance Tips

1. **Memory allocation**: Use appropriate Java options for your project size
2. **Output directory**: Use SSD storage for better I/O performance
3. **Chain limits**: Use `--max_chains` to limit analysis for large projects
4. **Logging**: Redirect logs to avoid console output for large projects

## Advanced Usage

### Custom Analysis

You can extend the analysis by modifying the `FlashAgent` class:

```python
# Example: Custom chain filtering
flash_agent = FlashAgent("chains")
flash_agent.load_chains()

# Filter chains by complexity
filtered_chains = flash_agent.filter_chains(
    min_steps=2,
    max_steps=10,
    min_complexity=1.0,
    max_complexity=5.0
)
```

### Batch Processing

For multiple projects, you can create a batch script:

```bash
#!/bin/bash
for project in project1 project2 project3; do
    python run_flash_only.py \
        --flash_jar flash.jar \
        --project_path "projects/$project" \
        --output_dir "results/$project"
done
``` 
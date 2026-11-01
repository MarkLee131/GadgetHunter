# GadgetHunter

[![FSE 2026](https://img.shields.io/badge/FSE-2026-0a7bbb)](https://doi.org/10.1145/3797065) [![License: Apache 2.0](https://img.shields.io/badge/License-Apache--2.0-d22128)](LICENSE)

GadgetHunter detects potential Java deserialization gadget chains using static taint analysis, LLM-based reachability checks, and Z3 constraint solving.

[Project page](site/index.html) · [Quick start](#quick-start) · [Results](#results) · [Usage reference](docs/usage.md) · [Paper & citation](docs/research.md)

## Quick start

### 1. Prepare the environment

You need **Python 3.10+** and **JDK 17+** to run the Flash backend. Automatic candidate generation runs against any target JDK you point it at (**Java 8, 11, 17 and newer**) and needs no API key. Chain analysis additionally requires matching Java sources and an **OpenAI API key**.

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

The default model is GPT-4.1; override it with `--model` or `--config`. See [configuration](docs/usage.md#configuration) for optional JDK source lookup and logging settings.

### 2. Generate candidate chains

Prepare rules and search for candidate chains in one command. Put JDK 17's `java` on `PATH`; `--java-home` identifies the separate target runtime (any version).

```bash
python scan_candidates.py --app /absolute/path/application.jar \
  --java-home /absolute/path/to/target-jdk \
  --output /absolute/path/to/prepared-scan \
  --collector fair --timeout 300 --heap-mb 4096
```

`--app` accepts ordinary JARs, Spring Boot fat JARs and WARs; nested libraries are extracted, and classes the target runtime cannot load are listed in the manifest. Add repeated `--lib /path/dependency.jar` arguments for other dependencies. This stage makes no LLM calls and needs no taint YAML: sources, sinks, propagation and ignores are derived automatically. The default `auto` profile combines native callback roots, common JDK propagation, checked ignores and modern effects (class definition, expression evaluation, JDBC, file, network, secondary deserializers), and adds reflection boundaries when your bytecode uses reflection. The manifest lists missing dependencies and unimplemented APIs; `enhance_scan.py --mode llm-gaps` lets a model propose rules for those, clearly labeled as hypotheses. See [automatic taint configuration](docs/usage.md#automatic-taint-configuration).

Candidates are exported to `<prepared-scan>/chains` and then triaged: `chains.review` holds one representative per cluster, with new routes through target classes first and known public chains or routes the scanned JDK/library build already blocks last. `triage.json` explains every label; nothing is removed. See [candidate triage](docs/usage.md#candidate-triage). Inspect `stage1.json` for progress and coverage: a timeout retains available complete chains and returns `partial`, not a clean verdict. If you already have a chains file, skip this step or rank it with `triage_candidates.py`.

Optional: [wrapper enhancement](docs/usage.md#experimental-wrapper-enhancement) derives checked transfer rules in a separate preparation. Deterministic inference is the default; LLM proposals are experimental and pass the same independent validator.

### 3. Analyze the chains

Start with one chain. Set `--project-root` to the directory containing the target's Java sources, including dependency sources needed by the chain. Chain indices start at zero. Pass `chains.review` to spend model calls on the best-ranked cluster representatives.

```bash
cd multi-agents
export OPENAI_API_KEY="your-api-key"
python main.py \
  --chains-file /absolute/path/to/output/chains \
  --project-root /absolute/path/to/target-sources \
  --chain-index 0
```

Then analyze a batch from the same `multi-agents/` directory:

```bash
python main.py \
  --chains-file /absolute/path/to/output/chains \
  --project-root /absolute/path/to/target-sources \
  --batch --max-chains 200
```

Add `--check` to validate inputs without API calls. Use `--resume /path/to/run-directory` with the same inputs and settings to continue an interrupted chain-analysis run.

Prefer a browser? Run `python workbench.py --java-home /path/to/target-jdk` from the repository root and open [localhost:8765](http://127.0.0.1:8765). Upload JARs or WARs to generate and triage candidates, then add matching Java sources for chain analysis. See [workbench usage](docs/usage.md#local-web-workbench). The [project page](site/index.html) summarizes the workflow for new users.

## Results

Paths below are relative to `multi-agents/` when using the commands above.

| Run | Main output |
| --- | --- |
| Summary | `results/<run>/summary.json` |
| Chain verdicts | `results/<run>/batch_scan_chains_report.csv` |
| Chain details | `results/<run>/chainN/analysis_results/analysis_result_chainN.json` |

Read `conclusion.verdict` in each result:

| Verdict | Meaning |
| --- | --- |
| `FEASIBLE` | The extracted constraints are satisfiable. |
| `NOT_FEASIBLE` | The solver returned `unsat` for the extracted constraints. |
| `UNKNOWN` | Evidence is missing, a constraint is unsupported, or the solver was inconclusive. |
| `EARLY_STOP` | A region edge was judged unreachable; constraint analysis was skipped. |
| `ERROR` | Analysis failed; inspect the error details. |

`FEASIBLE` is a constraint-based finding, not confirmation from executing a payload. This repository does not include an exploit generator. See [result fields and filtering](docs/usage.md#result-fields-and-filtering) for investigation steps.

## Documentation and source

| Resource | Contents |
| --- | --- |
| [Usage reference](docs/usage.md) | Configuration, output fields, filtering, troubleshooting |
| [Engine design](docs/architecture.md) | Execution model, reuse rules, validation, and remaining work |
| [Dependency evaluation](evaluation/README.md) | Pinned library versions, independent policy checks and scan reproduction |
| [Automatic taint configuration](docs/adaptive-taint-design.md) | Built-in profiles, JDD/code review, recent vulnerability lessons, triage catalog, adaptive-rule design |
| [Research artifact](docs/research.md) | Paper, BibTeX, pipeline, experiment settings, benchmark results |
| [Core implementation](multi-agents/) | CLI, agents, prompts, analysis tools, and Flash backend |
| [Gleipner benchmark](gleipner_results/) | Configurations and saved Stage-1 outputs |
| [Figure data](analysis_scripts/README.md) | CSVs and plotting instructions |

## License

Source code is licensed under [Apache 2.0](LICENSE), except the LGPL [backend helper](backend/strings/README.md) and [collector adapter](backend/fair/README.md). The bundled modified `flash.jar` includes components under separate licenses; see [third-party notices](THIRD-PARTY-NOTICES.md) and [license texts](licenses/).

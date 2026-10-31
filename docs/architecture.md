# Detection engine design

[Back to README](../README.md)

GadgetHunter separates candidate generation, semantic analysis, constraint solving, and scan execution. The current iteration makes results recoverable and uncertainty explicit, while preserving the research pipeline.

[`prepare_scan.py`](../prepare_scan.py) now builds experimental Java 8 native-deserialization configurations from class metadata and reusable profiles. See the [adaptive taint design](adaptive-taint-design.md) for the JDD comparison, protocol requirements, model-proposal validation and implementation boundaries.

[`enhance_scan.py`](../enhance_scan.py) derives bounded wrapper summaries and produces a separate preparation. Deterministic inference is the default; optional model proposals pass the same whole-method bytecode validator. The current verifier supports reference-return copies/casts and reviewed stream-constructor composition, and defers effects, branches, field operations and unknown calls. Configuration, validator and target fingerprints are checked before an enhanced scan starts.

CLI and local web scans can build a fingerprinted optimization over the bundled backend's fixed-pattern string helpers. It preserves roots and rule semantics, with stock-backend comparison available. Progress reports now identify that phase and current sink.

## Execution model

```text
Modified Flash → candidate chains + matching Java sources
                              ↓
                   ScanSession (CLI / local web worker)
                 input fingerprint / checkpoints
                              ↓
                  RegionBasedCoordinator
             region partition → reachability → constraints → Z3
                              ↓
                per-chain evidence + JSON/CSV reports
```

`tools/analysis/scan_session.py` owns checkpointing, deduplication, and report generation without depending on CLI arguments. A web worker can call the same interface. `main.py` validates user input and constructs the coordinator. `scan_candidates.py` now invokes preparation and Flash as a bounded first stage; it exports complete candidate blocks and a `stage1.json` execution/coverage report. The LLM analysis remains a subsequent stage.

The coordinator and its agents hold mutable output paths and token counters. Execution remains sequential within a scan. Threading this coordinator would mix evidence and accounting between chains; parallel execution needs isolated worker instances and a bounded API budget first.

## Result contract

| Outcome | Required evidence |
| --- | --- |
| `FEASIBLE` | Successful solver process with one explicit `sat` result |
| `NOT_FEASIBLE` | Successful solver process with one explicit `unsat` result |
| `EARLY_STOP` | An explicit negative reachability decision from the model |
| `UNKNOWN` | Missing source, ambiguous model decision, unsupported/incomplete constraints, or inconclusive solver result |
| `ERROR` | API, script, or analysis execution failure |

Constraints the translator cannot encode must not be silently dropped. Unsupported runtime predicates such as cast compatibility currently produce `UNKNOWN`. `FEASIBLE` remains a finding under the extracted model; runtime predicates still need independent facts about the actual application environment, and no payload execution is performed.

## Reuse and recovery

- Whole-chain reuse requires identical edge sequences within the same scan. IDs and duplicate provenance remain in the report.
- Model-response reuse is bounded in memory and requires identical source/context prompts, system prompts, provider, model, and request parameters. Failed or ambiguous reachability responses are not cached. Origin chain IDs point to the original logs.
- Each completed chain gets an atomic JSON checkpoint. A process lock prevents concurrent writers to the same run directory.
- Resume requires matching input, source, configuration, prompt, and implementation fingerprints. Inconclusive and failed chains are retried. Cache state is local to the process; checkpoints survive restarts.

## Validation

Run the offline suite from the repository root after installing dependencies:

```bash
python -m unittest discover -s tests -v
```

The tests execute real Z3 processes and include a CLI integration test with real Java parsing and fixed model responses. They cover status interpretation, incomplete constraints, timeout, request reuse, duplicate chains, interruption, corrupted checkpoints, source/model changes, and resume.

With `GADGETHUNTER_TEST_JAVA8_HOME` set, the suite also runs the actual Flash search on explicitly selected fixture callbacks. It verifies controlled command and nested-deserialization candidates and excludes a constant-command negative case. Other first-stage regressions cover timeouts, partial output, malformed/truncated blocks, rule loading and preservation of existing evidence.

## Next engineering milestones

1. **Benchmark the detector.** Supply matching sources and target JARs for labeled projects; record recall, false-positive rate, `UNKNOWN` rate, wall time, tokens, and cost. Compare cold runs and resumed runs on identical inputs.
2. **Strengthen the constraint model.** Use method-scoped variables and a typed intermediate representation; validate runtime predicates against actual classpaths, JDK versions, and module settings. Expand supported predicates with positive and negative regression cases.
3. **Reduce source and API work.** Index source files once, cache parsed methods by content, then add isolated workers with explicit request/token limits. Measure each change against the same labeled workload.
4. **Broaden the web workflow.** The local workbench now accepts JAR/dependency uploads, uses a server-configured Java 8 runtime, runs baseline/enhanced searches, and passes retained candidates to source analysis. It provides progress, cancellation, fresh candidate retries, chain-analysis resume and evidence browsing. Add modern runtime/archive support and verify browser interactions. Generated solver scripts currently execute locally; hosted execution needs an isolated worker environment before accepting uploaded targets.

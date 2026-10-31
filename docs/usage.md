# Usage reference

[Back to README](../README.md)

## Local web workbench

From the repository root, after installing the Python dependencies:

```bash
python workbench.py --java8-home /path/to/target-jdk8
```

Open <http://127.0.0.1:8765>. In **Find candidate chains**, upload application archives (JAR, Spring Boot fat JAR or WAR) and dependency JARs, choose the effect coverage, Java heap and time limit, and start a scan. Built-in rules and deterministic wrapper enhancement need no API key. JDK 17+ runs Flash; `--java8-home` supplies the distinct target runtime, and `--java` can select the host executable. The server processes one job at a time.

The overview shows preparation/search phases, backend method counters and available results. **Scan details** exposes indexed classes, loaded rules, unresolved dependencies, search limits, candidate provenance and **Review priority**: the [triage](#candidate-triage) summary and the best-ranked cluster representatives with their labels. Comparisons run the baseline and enhanced searches separately, each with the chosen time limit; preparation and optional model requests take additional time. Complete candidates are retained and merged even when a search times out or enhancement fails. Their presence or absence is not a vulnerability verdict.

Choose **Analyze candidates** on a finished job, upload matching target/dependency Java sources as a ZIP, and start with a small chain limit. **Chains to analyze** defaults to one representative per review cluster in triage order; every candidate in review or search order is also available. Alternatively, upload an existing `chains` file. Chain analysis and optional LLM rule proposals require `OPENAI_API_KEY` in the server environment before startup. Source context or selected bytecode is sent to the configured model provider for those stages; the browser never receives the key. Candidate scans can be cancelled and run again in a fresh job; chain analysis supports resume. Cancellation during preparation or a model request takes effect when that operation returns.

Jobs, uploads and results are stored in `.gadgethunter/jobs/`; use `--data-dir` to choose another directory and `--port` to change the port. Candidate jobs retain `baseline/`, optional `enhanced/`, merged `chains`, and `candidate-index.json` recording which phase found each chain. The service binds to loopback only. Archive uploads allow at most 64 files and 256 MiB combined (360 MiB encoded HTTP request). Source/chain submissions retain their 32 MiB encoded limit; only `.java` entries are extracted from source ZIPs. The same Java 8 target and archive normalization as the CLI apply.

The page also works as a static report explorer: import per-chain result JSON files or an exported array, filter findings, inspect constraints and download results. Imported reports stay in the browser session. A hosted/static copy cannot run Java or Python scans; use the local workbench for execution.

## Bounded candidate generation

`scan_candidates.py` prepares a Java 8 native-deserialization configuration and executes Flash without an API key or handwritten taint YAML:

```bash
python scan_candidates.py --app /path/application.jar --lib /path/dependency.jar \
  --java8-home /path/target-jdk8 --output /path/new-scan \
  --timeout 300 --heap-mb 4096 --stack-mb 16
```

Repeat `--app`/`--lib` for additional JARs or class directories. `--java` selects the JDK 17+ executable running Flash; it is distinct from the target Java 8 runtime. No profile flags are needed: the default `auto` selection is described in [automatic taint configuration](#automatic-taint-configuration).

Spring Boot fat JARs, WARs and multi-release JARs can be passed directly. Preparation writes ordinary JARs to `<output>/classpath`: `BOOT-INF/classes` and `WEB-INF/classes` become application classes, nested `lib/*.jar` entries become libraries, and launcher classes are skipped. A Java 8 runtime cannot load multi-release overlays, `module-info` or classes newer than bytecode 52, so these are dropped. A duplicate class keeps its first definition in classpath order (runtime, then applications, then libraries), as the JVM does. `manifest.json.classpath_normalization` lists every dropped or shadowed class, and the manifest limitations state counts. Unchanged ordinary JARs are used in place.

| Artifact | Purpose |
| --- | --- |
| `manifest.json` | Resolved rules, callback roots, target identity and preparation gaps |
| `stage1.json` | Live method counters, rule-load verification, limits, status and elapsed time |
| `backend.log` | Full backend diagnostics |
| `chains` | Complete, validated candidate blocks available for subsequent analysis |
| `output/chains` | Raw backend output, retained for investigation |
| `triage.json` | Review labels for every candidate, clusters and the catalog hash; see [triage](#candidate-triage) |
| `chains.review` | One representative per cluster, in review order; the recommended input for chain analysis |
| `chains.ranked` | Every candidate, in review order |

Exit codes are `0` for a completed bounded search, `2` for partial coverage, `1` for a backend/output failure, and `130` for cancellation. A wall timeout or Ctrl-C terminates the backend process group and preserves complete candidate blocks. A nonzero backend exit cannot become a successful scan merely because it emitted some chains. Empty candidate output requires a consistent completion footer and verified rule loading before it is accepted as a completed search.

The default heap is 4 GiB and stack 16 MiB, configurable for the target. The timeout covers backend execution; preparation runs first. Flash also applies chain-length, sink-search and similarity limits. Its default collector does not report every internal budget exhaustion; a completed process is not exhaustive coverage or proof of safety. All selected native callback roots are retained; this runner does not filter packages to reduce runtime. Full-runtime searches can be expensive even for small applications.

CLI and local web scans use `--backend auto` by default. For the validated bundled JAR, a matching JDK compiler builds a small string-parsing optimization before execution. `stage1.json` records its source/artifact hashes and compiler, or the reason for falling back to the stock backend. Use `--backend stock` for an unmodified comparison or `--backend optimized` to require the optimization. Compilation adds setup time outside the search budget. Progress now distinguishes call-graph analysis from collection and identifies the current sink.

Each candidate-generation attempt requires a fresh output directory. Its current checkpoints expose progress and retain findings; they do not resume the JVM's in-memory graph. Chain analysis has separate resume support described below.

### Automatic taint configuration

Preparation derives all four parts of the backend configuration from the target; nothing is handwritten.

| Part | Source of rules | Check before use |
| --- | --- | --- |
| Sources | Native callbacks declared by Serializable classes: `readObject`, `readObjectNoData`, `readExternal`, `readResolve`, and `validateObject` on `ObjectInputValidation` | Exact signatures from class metadata |
| Sinks | `native-core`, `modern-effects`, optional `reflection-boundaries` | Signatures resolved on the classpath; missing library rules listed |
| Derived boundaries | Target methods that pass a parameter into `new ObjectInputStream(...)`, directly or through a stream wrapper (`SerializationUtils.deserialize`, `fromBytes(byte[])` helpers) | Exact instruction pattern; the parameter slot must never be reassigned. Listed in `manifest.json.derived_boundaries` |
| Propagation | `jdk-propagation` (strings, builders, arrays, `System.arraycopy`, Base64/URL decoding, stream wrappers) plus profile transfers | Every `jdk-propagation` transfer must be non-overridable on this classpath, because a transfer replaces the callee and would hide a gadget override |
| Ignores | `jdk-propagation` leaf calls (`String.length`, `String.equals`, `Math.max`, clocks and similar) | Closed-world proof over the scanned classpath: primitive result, no overridable or unknown call, no invokedynamic, no reference stores. Refused rules are listed with the reason |

Flash skips an ignored call entirely and replaces a transferred call's body, so an unsafe rule would hide chains silently. That is why ignores of `hashCode`, `equals(Object)` on open classes, `toString`, comparators and logging are never predefined: those calls are deserialization triggers.

The default `--profile auto` selects `native-core`, `jdk-propagation` and `modern-effects`, and adds `reflection-boundaries` when application or library bytecode calls `Method.invoke` or `Constructor.newInstance`. `manifest.json.profile_selection` records each reason. Pass explicit `--profile` values to override it.

`manifest.json.coverage_gaps` reports what the search cannot follow:

- `missing_packages`: classes the target calls that are not on the classpath. Add those JARs with `--lib`; otherwise those calls are dead ends.
- `unimplemented_methods`: abstract methods the target calls with no implementation on the classpath, such as SPI interfaces, runtime-generated classes (SpEL `CompiledExpression`, cglib `FastClass`) or implementations shipped separately.

To adapt rules to those gaps, run `enhance_scan.py --prepared <scan> --output <new> --mode llm-gaps`. One request sends method signatures and caller names (no bytecode) to the model, which classifies each method as a sink with an effect family, a transfer, or neither. Proposals pass schema, identity, index and effect-family checks, but there is no body to verify them, so they are **hypotheses**: they go into a separate preparation, and triage marks every candidate that relies on one as `constrained` with an `llm-hypothesis` note. On the Spring Boot demo, one request (about 5,000 tokens) proposed SpEL `CompiledExpression.getValue` as expression evaluation and cglib `FastClass.invoke`/`newInstance` as reflective invocation.

### Effect coverage

`modern-effects` adds effect boundaries that still matter on patched runtimes; `auto` includes it. Library rules resolve only when the library is on the classpath; absent owners are listed as unresolved rules, not errors.

| Family | Boundaries |
| --- | --- |
| Class definition | `ClassLoader`/`SecureClassLoader.defineClass`, `Unsafe.defineClass`/`defineAnonymousClass`, `URLClassLoader.newInstance`, `GroovyClassLoader.parseClass` |
| Expression evaluation | `ScriptEngine.eval`, EL `ELProcessor`/`ValueExpression`/`MethodExpression`, SpEL `Expression.getValue`, MVEL, `GroovyShell.evaluate` |
| JDBC | `DriverManager.getConnection`, `Driver.connect`, `DataSource.getConnection` |
| File | `FileOutputStream`/`FileWriter` constructors, `Files.write`/`copy`, `File.renameTo`, `File.delete` |
| Network | `URL.openConnection`/`openStream`, `InetAddress.getByName` |
| Secondary deserializers | `XMLDecoder.readObject`, XStream `fromXML`, SnakeYAML `load`, Hessian `readObject`, fastjson `parse`/`parseObject` |

Parsing and construction propagate taint; the later evaluation, connection or write is the boundary. Library signatures were checked against Spring Expression 5.3, Tomcat EL 9.0, Groovy 3.0, XStream 1.4, SnakeYAML 2.x, Hessian 4.0, fastjson 1.2 and MVEL 2.4. More sinks enlarge the search, so expect more candidates and longer scans than `native-core` alone.

### Candidate triage

`scan_candidates.py` triages candidates after every search. To triage existing output:

```bash
python triage_candidates.py --prepared /path/scan
python triage_candidates.py --chains /path/old/chains --runtime-version 1.8.0_432 \
  --classpath /path/target-jdk8/jre/lib/rt.jar --classpath /path/dependency.jar
```

Triage never removes a candidate. It labels each one using [`rules/triage.yml`](../rules/triage.yml):

| Field | Meaning |
| --- | --- |
| `novelty` | `known` when a core gadget of a public family appears (CommonsCollections, CommonsBeanutils, ROME, Groovy, Spring, Hibernate, C3P0, URLDNS, JRMP client and others); otherwise `novel`. Reusable triggers and terminals such as `HashMap`, `PriorityQueue`, `BadAttributeValueExpException` or `TemplatesImpl` do not make a chain known. |
| `effect`, `priority` | Effect family of the sink. Nested reads from the callback's own stream propagate rather than end a path, so calls on the read object are followed; building a new `ObjectInputStream` over controlled data is reported as `secondary-deserialization`. `stream-continuation` remains for custom readers that only read their original stream. |
| `mitigations` | `blocked` when the scanned bytecode shows the route is dead, `constrained` when the effect needs more than the chain, `unverified` when evidence could not be read. |
| `runtime_only` | Every class on the route belongs to the target runtime. |
| `unserializable_receivers`, `implausible` | Receivers the stream cannot supply; three or more mark the route implausible. |
| `cluster_id` | Candidates with the same non-runtime classes and effect, or the same runtime route after the entry callback. |

Mitigations are checked against the target's own bytecode where possible: for example, whether `AnnotationInvocationHandler.readObject` calls `readFields` (JDK 8u71+), whether a Commons Collections functor's callback calls `FunctorUtils.checkUnsafeSerialization` (3.2.2), or whether a functor is still `Serializable` (4.1). Vendor backports and shaded copies are judged by what they contain, not their version string. JNDI remote-codebase defaults use the runtime version from `rt.jar`. Without class facts, nothing is marked blocked.

Review order is: not blocked, real effects before stream continuations, routes through target classes before runtime-only routes, plausible before implausible, novel before known, higher effect priority, then fewer unserializable receivers and shorter chains. "Novel" is relative to the catalog. Search public research before reporting, and treat every label as a review aid, not a verdict.

Pass `chains.review` to `multi-agents/main.py --chains-file` to spend model calls on cluster representatives. The workbench uses this selection by default and records each analyzed chain's original candidate ID and labels.

### Experimental fair collection

Add `--collector fair` to `scan_candidates.py` or the local `workbench.py` server to interleave searches across sinks. It retains each active search cursor between turns and gives direct source edges an early opportunity. `--backend auto` or `optimized` and a matching host JDK compiler are required. The default collector remains `stock`.

`stage1.json.collector` and `output/collector.json` report per-sink scheduled, finished, budget-exhausted and pending edge searches. Exhausted budgets produce `partial`, even on a normal backend exit. The workbench exposes this journal through **Scan details**. Scheduling changes can alter similarity pruning and emitted candidates, so preserve separate comparisons; see [semantics and limitations](../backend/fair/README.md).

### Experimental reflection boundaries

For reflection-heavy dependencies, add `--profile native-core --profile reflection-boundaries` to `prepare_scan.py`, `scan_candidates.py` or the local `workbench.py` server. This adds exact public-API rules without handwritten YAML. The default remains `native-core`.

The profile propagates class/name/signature selection into Method/Constructor objects and records `Method.invoke` / `Constructor.newInstance` as **reflection boundaries** when the selected member is tainted. It does not expand every possible reflective target. Invocation receiver/argument compatibility, access checks, actual type control, initialization effects and serialization policy remain to be established. A candidate ending at reflection is not a command-execution finding. Fixed reflective targets with controlled invocation arguments are not covered by this profile; receiver taint through `Object.getClass()` can overapproximate type control.

`reflection-dispatch` remains a separate alternative that attempts target expansion. The two profiles cannot be combined in one backend run: dispatch mappings override sink handling. Keep separate outputs when comparing them. See the [pinned real-dependency evaluation](../evaluation/README.md) for policy checks, observed gaps and reproduction commands.

### Experimental wrapper enhancement

After preparing a baseline, create a separate configuration with independently checked wrapper transfers:

```bash
python enhance_scan.py --prepared /path/baseline --output /path/enhanced
python scan_candidates.py --prepared /path/baseline --timeout 300
python scan_candidates.py --prepared /path/enhanced --timeout 300
```

Use `prepare_scan.py` to produce an unscanned baseline, or reuse a preparation from `scan_candidates.py` and skip its already completed baseline search. `--prepared` runs an existing preparation and cannot be combined with classpath/preparation flags. Each prepared directory can be scanned once.

The default enhancement is deterministic and makes no API calls. It supports straight-line reference-return wrappers, including exact `ByteArrayInputStream`/`ObjectInputStream` constructor composition under the existing built-in transfers. Methods containing effects, unknown calls, branches, field operations, exception handlers, synchronization or overridable dispatch are deferred. A summary proves bounded normal-return propagation under the baseline abstraction; it does not establish runtime reachability.

To try model-generated proposals, set `OPENAI_API_KEY` and add `--mode llm --model gpt-4.1`. This sends selected target bytecode and decoded instruction evidence to the provider. It makes one request with a 30-second timeout, no retries, at most 32,000 input bytes and 2,000 output tokens. `--max-methods` defaults to 30 and is capped at 100; inputs that exceed the request budget are rejected before sending. Model output passes identity, schema, instruction-evidence and independent whole-method validation. No model-generated code, ignores or sanitizers are executed or applied.

`enhancement.json` records selected methods, bytecode fingerprints, proof traces, rejected proposals, selection coverage and model token usage. The enhanced preparation preserves the original rules and adds only accepted transfers. Its configuration and target bytecode are checked again before launching Flash; regenerate after changes. Keep target artifacts unchanged during scans. Compare baseline and enhanced outputs and retain both: bounded search order can change, so adding summaries is not a recall guarantee. This first LLM mode is an experimental proposal path using the same limited validator; no advantage over deterministic inference has been established, and it is not a general adaptive taint engine.

## Flash configuration

Stage 1 uses the modified Flash backend bundled in `multi-agents/flash/flash.jar`. Its chain output includes call kinds, line numbers, and taint annotations consumed by the Python stages. Use this build when generating chains for GadgetHunter.

For a Java 8 native-deserialization scan, use [`prepare_scan.py`](adaptive-taint-design.md#implemented-first-step) to resolve built-in rules and generate the configuration from your target classpath. It also supplies the runtime directory layout expected by Flash. The initial profiles are experimental and do not establish application exposure or verify filters.

For benchmark reproduction or manual settings, start from the [Depth configuration](../gleipner_results/configs/config_depth.yml). Its knowledge file is specific to Gleipner and should not be used as a general security default. Adapt these fields:

| Field | What to supply |
| --- | --- |
| `appClassPath` | Target JARs or compiled class directories |
| `classPath` | Additional dependency class paths, if needed |
| `javaVersion` | Target Java version; the supplied configurations use `8` |
| `outputDir` | Directory for candidate chains and analysis output |
| `analyses.method-summary` | `priori-knowledge:/absolute/path/to/knowledge.yml`; the [Gleipner knowledge file](../gleipner_results/configs/Gleipner_baseline_priori-knowledge.yml) is a benchmark example |
| `GC_OUT` | Candidate-chain filename, defaulting to `chains` in the supplied configurations |

The shell runner changes into the configuration file's directory before starting Java. Relative paths inside the configuration are resolved there. Use absolute paths for both the configuration argument and its path fields to avoid ambiguity. The benchmark JAR paths in the example refer to an external benchmark checkout; those target JARs and sources are not included in this repository.

With the supplied `prependJVM: false` and `javaVersion: 8`, the bundled backend also expects the target runtime JARs under `<config-directory>/java-benchmarks/JREs/jre1.8/`. An external Java 8 target runtime is required in addition to the JVM used to run Flash. The preparation command creates links to it automatically.

Run from the repository root:

```bash
bash multi-agents/flash/run.sh /absolute/path/to/config.yml
```

The runner uses `java` from `PATH`; it needs JDK 17. It writes `log.log` beside the configuration. Default JVM flags are `-Xss1024m -Xmx24G`; override `FLASH_JAVA_OPTS` to fit your machine and target. Deep chains may require a large stack. `FLASH_JAR` optionally overrides the bundled JAR path.

To process a directory containing one `config.yml` per target subdirectory:

```bash
bash multi-agents/flash/run.sh --batch /absolute/path/to/targets 2
```

The final argument limits concurrent jobs (default: 8). Each job has its own JVM memory budget. Targets with an existing `time` file are skipped.

## Configuration

`main.py` loads JSON with `--config /path/to/config.json`. CLI flags override file settings; omitted settings use defaults. Keep credentials in environment variables.

```json
{
  "llm_type": "gpt",
  "llm_model": "gpt-4.1",
  "max_chains": 0,
  "solver_timeout": 30,
  "max_fix_attempts": 3,
  "llm_timeout": 60,
  "llm_max_retries": 2,
  "llm_cache_size": 256
}
```

| Setting | Behavior |
| --- | --- |
| `OPENAI_API_KEY` | Credential for `llm_type: gpt` |
| `DEEPSEEK_API_KEY` | Credential for `llm_type: deepseek`; also set an appropriate `llm_model` |
| `GADGETHUNTER_JDK_DIR` | Optional parent of `jdk8u/jdk/src/share/classes` for JDK source retrieval |
| `EXTRACT_JAVADOC=0` | Disables Javadoc context; JSON `extract_javadoc` overrides this |
| `--model` | Overrides `llm_model` |
| `--debug` | Enables verbose logging |
| `--max-chains N` | Batch limit; default `0` analyzes all chains |
| `--solver-timeout N` | Seconds per solver process; timeout yields `UNKNOWN` without LLM repair |
| `--output-dir` | Parent directory for new runs (default `results`) |
| `--check` | Validates chains and sources and counts duplicates without calling an API |

`llm_cache_size` bounds the number of validated, identical-request responses reused within a scan; `0` disables this cache. Whole-chain deduplication still applies. API timeout/retry settings currently apply to the GPT and DeepSeek clients.

`--project-root` must contain matching `.java` files, including relevant dependency sources. Compiled JARs alone do not provide source context. Missing method source yields `UNKNOWN` rather than an inferred negative finding.

## Resume and reports

Each chain result is written atomically before the next chain starts. Reuse a run directory by repeating the same inputs and analysis settings:

```bash
python main.py --batch \
  --chains-file /absolute/path/to/chains \
  --project-root /absolute/path/to/sources \
  --resume /absolute/path/to/results/run-directory
```

Resume verifies chain contents, Java and optional JDK source contents, model and analysis settings, prompts, and engine code. A mismatch requires a new run. `ERROR`, `UNKNOWN`, missing, or corrupt checkpoints are reanalyzed. You may increase `--max-chains` when resuming. Existing reports from before `scan.json` was introduced cannot be resumed through this mechanism.

Within a run, identical chains share analysis while retaining their original indices. `reused_from_chain` identifies the chain holding the original supporting logs. Exact-request cache hits include `cache_hit` and `cache_source_chain` in their analysis metadata. A scan directory permits only one active writer.

Both single-chain and batch modes write `summary.json`, `batch_scan_chains_report.csv`, and per-chain JSON under the run directory. The legacy `test_single_chain.py` still writes its separate `single_chain_results/` summary; use `main.py --chain-index N` for checkpointed runs.

Exit codes: `0` completed without errors or unknowns; `1` input/runtime error or an `ERROR` result; `2` at least one `UNKNOWN` and no errors; `130` interrupted. Exit code `0` does not mean the project is vulnerability-free: inspect the verdicts and the candidate-generation coverage.

To rebuild historical reports without an API key:

```bash
python main.py --rebuild /absolute/path/to/results/run-directory
```

## Result fields and filtering

Results are stored as one JSON file per chain. The legacy single-chain script wraps these fields in `analysis_result` and adds `test_metadata`.

| Field | Contents |
| --- | --- |
| `original_chain` | Input chain edges |
| `region_analysis` | Parsed gadgets, regions, transitions, and metadata |
| `semantic_analysis` | Reachability outcome, or the failed edge when analysis stops early |
| `feasibility_analysis` | Solver status, extracted constraints, model, and solver errors |
| `conclusion` | Verdict and reasoning |
| `analysis_time`, `error` | Runtime and top-level error details |

For chains reaching constraint analysis, inspect `feasibility_analysis.solver_status` alongside the verdict:

- `sat`: the extracted constraints are satisfiable.
- `unsat`: the extracted constraints are unsatisfiable.
- `unknown` or `error` (sometimes uppercase): no conclusive solver result; inspect `error_message` and the generated scripts.

`NOT_FEASIBLE` now requires an explicit `unsat` result. Missing or unsupported constraints yield `UNKNOWN`; script crashes yield `ERROR`, even if a status was printed before the crash. `feasibility_analysis.json_constraints` exposes the ⟨Vars, Flow, Guard, Runtime⟩ representation for review. Historical results predating this change may have conflated these outcomes.

For `EARLY_STOP`, `feasibility_analysis` instead contains `early_stop` and `reason`; no solver result is available. The conclusion includes the failed edge and the early-stop reason.

To extract feasible chains using a batch CSV, run from `multi-agents/`:

```bash
python extract_chains_by_verdict.py \
  --csv /absolute/path/to/batch_scan_chains_report.csv \
  --chains /absolute/path/to/original/chains \
  --verdict FEASIBLE \
  --output /absolute/path/to/feasible-chains.txt
```

Use the original chains file analyzed in that run so chain indices align. The filter also accepts `NOT_REACHABLE`, but the current coordinator reports that outcome as `EARLY_STOP`.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Flash fails or no chains appear | Read `log.log` beside the config; verify JDK 17, target/knowledge paths, and the JVM memory budget. |
| Python reports a missing API key | Export `OPENAI_API_KEY` in the shell running the command. |
| Java methods cannot be located | Supply matching `.java` files under `--project-root`; configure JDK source lookup for JDK methods. |
| No chain is selected | Verify the chains file is nonempty and `--chain-index` is within its zero-based range. |
| A verdict is inconclusive | Inspect `solver_status`, `error_message`, and per-chain files; rerun the chain with `--debug`. |

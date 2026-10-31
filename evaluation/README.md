# Pinned real-dependency evaluation

This suite separates **candidate-search observations** from an independently checked **serialization-policy label**. It does not assign vulnerability labels from a dependency version or compute precision/recall from candidate totals.

The first family is Apache Commons Collections. The [official security report](https://commons.apache.org/proper/commons-collections/security.html) describes two different protections: 3.2.2 adds a default rejection that can be re-enabled with a system property; 4.1 removes Serializable support from unsafe functors. The pinned [catalog](dependencies.json) includes 3.2.1, 3.2.2, 4.0 and 4.1, with exact artifact sizes and SHA-256 hashes. No dependency binaries are committed here.

## Policy oracle

[`SerializationPolicyProbe.java`](SerializationPolicyProbe.java) constructs one InvokerTransformer containing the harmless name `toString`. It never calls `transform`, creates a trigger graph, starts a process, or contacts an endpoint. For serializable releases, it writes this marker in memory with serialization enabled, then attempts a read in a separate default/enabled policy case. For a non-Serializable release it reports the structural restriction. Each policy case uses a new Java 8 process without inherited Java options or credentials.

These labels apply to the isolated functor and native protocol. They do not establish that a complete candidate object graph can be materialized, that an application accepts untrusted data, or that all other paths in a fixed library are safe. Objects created inside a callback need not be Serializable, so this oracle must not become a blanket class-pruning rule.

A second fixed oracle, [`MarkerGraphProbe.java`](MarkerGraphProbe.java), checks a HashMap → TiedMapEntry → LazyMap → InvokerTransformer callback route. Its reflected method is always the local marker's `toString`; its only effect is incrementing an in-memory counter. The serialized bytes never leave memory. The probe cannot accept an arbitrary method name or action. It adds a local marker class that is absent from the library-only static scans, so its result is not a same-classpath recall label.

## Run

Use a JDK 17+ host and the separate Java 8 target runtime. From the repository root:

```bash
python evaluate_dependencies.py --java8-home /path/target-jdk8 \
  --output /tmp/collections-policy-check --policy-only

python evaluate_dependencies.py --java8-home /path/target-jdk8 \
  --case collections-3.2.1 --case collections-3.2.2 \
  --profile native-core --profile reflection-boundaries \
  --collector fair --timeout 120 --heap-mb 4096 \
  --output /tmp/collections-boundary-scans
```

By default the script reads `~/.m2/repository`; change this with `--maven-repository`. `--fetch` downloads missing pinned JARs from Maven Central. Mismatched bytes are rejected before the policy probe executes. The selected artifact is copied into the new evidence directory. All runs require a fresh output directory and retain per-case failures; an interrupted run does not restart automatically.

`evaluation.json` includes artifact/probe/catalog identities, both policy and marker checks, runtime versions, search status, rule/inventory/backend hashes, budgets, collector journals, and zero-based candidate IDs involving the library or InvokerTransformer. `marker_graph_shape_candidate_ids` checks the callback and ordered owners of the marker route; even a shape match is not proof of feasible data flow. Attribution checks actual caller/callee owners, not class names mentioned as parameter types. Each case directory retains its full `stage1.json`, manifest, backend log and complete candidate chains. A timeout stays `partial`; the CLI returns 2 for partial evaluations, 1 for failures, and 130 for cancellation. A policy-only `completed` result means the oracle checks passed, not that the library was scanned.

No LLM is used. All runtime callbacks selected by normal preparation remain enabled. Compare separate runs of `native-core`, `native-core` plus `reflection-dispatch`, and `native-core` plus `reflection-boundaries`; do not combine the latter two in one run. Record ordering versions, since search order and similarity pruning affect bounded outputs. More candidates do not establish greater recall.

## Recall check across gadget families

[`benchmark_recall.py`](../benchmark_recall.py) scans vulnerable releases of public gadget families listed in [`recall-cases.json`](recall-cases.json) with the default automatic configuration and a fixed budget. A case counts as recalled when some candidate uses the family's core gadget and ends at an expected effect family; this is a candidate-level check, not an exploit test. `best_rank` is the position of the best such candidate in the triage review order (zero-based), which approximates how much review effort a user needs before reaching it.

```bash
python benchmark_recall.py --java8-home /path/target-jdk8 --output /tmp/recall --timeout 300
```

Use the same budget and machine when comparing a rule or backend change against an earlier run. A scan that exhausts its collector budget ends `partial`, so its recall is a lower bound for that budget.

# Evaluation on the Gleipner benchmark

This directory packages the Gleipner-benchmark artifacts that back
Section 5.2.2 ("Evaluation on the Gleipner benchmark") and Table 5 of the
paper. Gleipner [1] is a public, synthetic benchmark whose sink class
(`gleipner.core.SinkGadget.sinkMethod(String)`) only records a string for
test assertions, so the chains shipped here are reproducibility artifacts,
not exploit primitives.

## Layout

```
gleipner_results/
├── configs/                                # Run configs used to invoke the static stage
│   ├── config_depth.yml
│   ├── config_polymorphism.yml
│   ├── config_multipath.yml
│   └── Gleipner_baseline_priori-knowledge.yml   # Sinks / transfers / ignores spec
├── scripts/
│   └── flash_to_gleipner_basic.py          # Converts taint output to Gleipner "basic" format
└── taint-analysis/
    ├── gleipner.chains-1.0-depth/
    ├── gleipner.chains-1.0-polymorphism/
    └── gleipner.chains-1.0-multipath/
        ├── chains              # Raw edge-level taint output
        ├── chains_basic.txt    # Gleipner-evaluator "basic" format (post-conversion)
        ├── config.yml          # Frozen copy of the config used for this run
        ├── flash.log, log.log  # Static-stage logs
        ├── flash_time, time    # Wall-clock timings (seconds)
```

## Reproducing Table 5 (GadgetHunter row)

| Category     | TP cases | GadgetHunter | Missing benchmark IDs                |
| ------------ | -------- | ------------ | ------------------------------------ |
| Depth        | 20       | 14 / 20      | 005, 006, 011, 014, 015, 016         |
| Polymorphism | 20       | 13 / 20      | 005, 010, 012, 013, 015, 018, 019    |
| Multipath    | 10       | 1 / 10       | 10 paths collapse to 1 (see below)   |

False positives in all three categories: 0.

The above counts are derived directly from the `chains_basic.txt` files
in this directory (one chain per blank-line-separated record).

## Notes on the result (matches §5.2.2 of the paper)

* **Depth / Polymorphism.** The remaining cases are absent from the call
  graph due to the time-bounded path collection and non-deterministic DFS
  order inherited from Flash [2]. As discussed in the paper, extending the
  collection budget recovers additional cases (16/20 and 15/20
  respectively); we ship the default-budget run here.
* **Multipath (1/10).** The Multipath suite uses a switch-based dispatch
  to invoke 10 distinct `LinkGadgetN.linkMethod()` intermediaries that all
  delegate to `SinkGadget.linkMethod()`. The method-summary computed for
  each `LinkGadgetN` collapses to the same direct transfer to
  `SinkGadget.linkMethod()`, so the 10 structurally identical paths reduce
  to a single chain in the output. This is an intentional precision /
  scalability trade-off of method-summary-based interprocedural analysis.

## Comparison context (Table 5)

The paper compares against GadgetInspector, Tabby, Crystallizer, ODDFuzz,
Flash, and JDD on the same benchmark. See Table 5 of the paper for the
full numbers; only the GadgetHunter row is reproduced from artifacts in
this directory.

## References

[1] Bruno Kreyssig and Alexandre Bartel. *Gleipner: A Benchmark for
    Gadget Chain Detection in Java Deserialization Vulnerabilities*.
    Proc. ACM Softw. Eng. 2 (FSE), 2025.

[2] Flash (the static-analysis backbone of GadgetHunter); see the paper
    for citation.

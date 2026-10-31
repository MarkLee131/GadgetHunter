# Backend string parsing optimization

This directory contains a modified copy of Flash/Tai-e's `pascal.taie.util.Strings`, from upstream revision [`458cdf58e255c8ba9631c2bf98f297be47c3717f`](https://github.com/CGCL-codes/Flash/blob/458cdf58e255c8ba9631c2bf98f297be47c3717f/src/main/java/pascal/taie/util/Strings.java). It retains the original **LGPL-3.0-or-later** license and notices; see [LGPL](../../licenses/LGPL-3.0.txt) and [GPL](../../licenses/GPL-3.0.txt). The repository's Apache license does not relicense this file.

Two helpers replace repeatedly compiled fixed regular expressions with ASCII scans:

- `isLegalContrValue` accepts exactly the original ASCII character set, including the empty string.
- `extractParamIndex` finds the first `param-` followed by ASCII digits. It preserves leading-zero behavior, integer overflow exceptions, embedded matches and the original no-match sentinel.

Other helper methods are unchanged. `StringsParityProbe` compares all five public methods against the bundled implementation for 30,100 cases, including invalid values, Unicode and overflow, plus 8,000 concurrent parser calls. It compares return values and exception categories, not diagnostic exception text.

[`scan_rules/backend.py`](../../scan_rules/backend.py) validates the base JAR and original helper fingerprints in `compatibility.json`, captures this source, and compiles only this file with a matching host JDK compiler, `--release 17` and annotation processing disabled. The generated `backend-overlay.jar` contains one class and precedes the original JAR on the JVM classpath. The original JAR is not modified. Each scan records the source, overlay and backend hashes and compiler version.

CLI and local web scans default to `--backend auto`: use the optimization when compatible, otherwise record why the stock backend was selected. `--backend optimized` requires it; `--backend stock` selects the unmodified backend for comparisons. Compilation is setup work outside the backend wall-time budget. With the separately opt-in [`--collector fair`](../fair/README.md), the overlay also contains the collector adapter and its analysis registry; this mode requires successful compilation and does not fall back silently.

This optimization does not change roots, taint rules, graph limits or collector budgets, and does not establish detector accuracy.

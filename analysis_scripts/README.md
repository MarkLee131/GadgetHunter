# Figure data

This directory holds the data plotted in the paper's two comparison figures and the script that
renders them.

```
ablation_study/comparison_fig/
  RQ1_FP_FN.csv            # Figure 5 — the six baselines and GadgetHunter
  RQ1_FP_FN.pdf            # Figure 5 as it appears in the paper
  ablation.csv             # Figure 6 — the five ablation variants
  ablation_comparison.pdf  # Figure 6 as it appears in the paper
  plot_comparison.py       # renders both PDFs from both CSVs
```

## Regenerating the figures

```bash
pip install pandas matplotlib numpy
cd ablation_study/comparison_fig
python plot_comparison.py
```

The script reads both CSVs from the current working directory, so run it from inside
`comparison_fig/`. It overwrites `RQ1_FP_FN.pdf` and `ablation_comparison.pdf` in place.

## Data format

Both CSVs use the same three-row layout: a column of row labels followed by one column per tool or
variant, with rows `FPR`, `FNR`, and `New GCs` in that order. `FPR` and `FNR` are percentages written
with a trailing `%`; `New GCs` is a count.

`FPR` is the share of reported chains that are not true positives. `FNR` is the share of the 34
established ysoserial chains that a tool does not report. `New GCs` counts the reported true
positives that are not among those 34.

`RQ1_FP_FN.csv` covers GadgetInspector, Tabby, Crystallizer, ODDFuzz, JDD, Flash, and GadgetHunter.
`ablation.csv` covers the ablation variants of §5.3: `SA` (Stage 1 only), `SA_SemReach`
(Stages 1–2, without SMT), `SA_LLMD` (Stage 1 plus black-box LLM validation), `SA_LLMC` (Stage 1 plus
one-shot LLM constraint extraction), and `GadgetHunter` (all three stages). `plot_comparison.py`
reorders `ablation.csv`'s columns to `SA, SA_LLMD, SA_SemReach, SA_LLMC, GadgetHunter` to match the
figure; the CSV itself stores them in a different order.

## Per-chain data

The per-chain traces these aggregates were computed from (~1.4 GB of LLM I/O and generated Z3 scripts
across the 22 ysoserial applications) are distributed separately rather than through this repository.

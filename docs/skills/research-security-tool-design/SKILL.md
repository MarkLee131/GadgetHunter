---
name: research-security-tool-design
description: Use when designing or reviewing interfaces and project pages for security research tools, especially chain analysis, static analysis, constraint solving, and research artifacts. Apply evidence-driven information hierarchy and domain-specific visual components; do not apply to unrelated marketing sites.
---

# Research Security Tool Design

Start with the reader's decision: which result deserves review, why it matters, and what evidence supports it. Use the research objects themselves to shape the interface.

## Before implementing UI

Explain why each proposed visual container exists. Name the information relationship or interaction it owns. If its only purpose is visual grouping or aesthetics, reconsider it.

Use these relationships as the component vocabulary:

| Relationship | Component | Required information |
| --- | --- | --- |
| Candidate identity in a ranked set | ChainRow | Actual rank, endpoints, effect and independent classification dimensions |
| Change in analysis responsibility | RegionBoundary | Boundary meaning and which analysis handles it |
| Classification or solver outcome | VerdictBadge | Explicit text and evidence scope, not color alone |
| Candidate consequence | EffectTag | Concrete effect, distinct from exploitability |
| Selected claim and its support | EvidencePanel | Source, target/runtime, coverage and analysis state |
| Conditions behind a solver result | ConstraintPanel | Extracted assumptions, solver outcome and unknowns |
| Data dependency between stages | PipelineNode | Input, transformation, output and local/remote execution |

These are semantic patterns, not a requirement to introduce a component framework. Follow the repository's existing technology.

## Evidence before visual polish

- Prefer actual exported records, traces and runnable commands. Preserve their original identifiers and ranks; if displaying zero-based ranks as one-based positions, apply that consistently.
- Identify fixtures, historical recordings and illustrative examples explicitly. Do not dress a fixture up as a production finding.
- Keep partial coverage and missing analysis visible. Do not infer SAT, confidence, vulnerability counts or exhaustive results from candidate generation.
- Model independent dimensions independently. In GadgetHunter, novelty and mitigation overlap: a candidate can be novel and blocked. Their counts are not additive partitions.
- Keep candidate discovery, semantic reachability, satisfiability and confirmed exploitation distinct.
- For each research claim, record its benchmark and exact paper section, figure or table. Separate original paper results from later engineering capabilities and current reruns.
- Link reproducible artifacts or source excerpts. Remove local machine paths and unrelated private metadata from public examples.

## Visual and editorial grammar

Lead with a concise proposition and inspectable analysis evidence. Use connected nodes for stages, a table for comparable measurements, a list/detail view for candidate inspection, and disclosures for raw traces.

Avoid generic SaaS hero stacks, meaningless gradients, repeated rounded feature cards, oversized KPI trios and decorative badges. Use whitespace, alignment and thin rules for prose; reserve bounded surfaces for evidence, playback and executable code. Color must communicate a defined state, with a text equivalent.

Write natural titles about the action or content. Do not join labels, actions and filenames with middle dots or substitute another decorative separator for the same construction. Put implementation filenames in code or technical documentation.

Information density should improve inspection: keep ranks, runtime, effects and analysis state near the result. Do not shrink text simply to fit more data.

## Interaction and delivery

- Preserve existing demos and resources. Check the actual publication root: a video existing in the repository does not mean the site publishes it.
- Give separate demonstrations clear names, visible entries, captions and provenance. Do not imply that a saved report is a fresh analysis or that filter inspection executes an exploit.
- Keep basic content readable without JavaScript. Support keyboard selection and announce compact result changes to assistive technology.
- Check narrow screens, long JVM names, unavailable evidence, clipboard denial, and video playback. Inspect screenshots as well as DOM assertions.
- Report local verification and deployment status separately. A working local preview does not establish that the public page changed.

## GadgetHunter case

For this repository, consult `docs/superpowers/specs/2026-11-02-security-research-homepage-design.md`, `docs/research.md`, `demos/workbench/README.md` and `demos/weblogic-coherence/README.md` from the repository root. The public example is in `site/evidence/triage-example.json`.

The recorded fixture scan has 2,729 candidates and 512 clusters with partial coverage. Its blocked route is also novel. Its candidate record has no feasibility result. The WebLogic recording compares filter decisions across two builds without executing a payload. These are examples of how to preserve evidence boundaries, not numbers to reuse in other projects.

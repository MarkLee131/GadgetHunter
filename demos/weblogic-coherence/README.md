# WebLogic Coherence filter rediscovery

A short narrated clip showing GadgetHunter's deserialization filter model reproduce a known Coherence gadget on an unpatched WebLogic build, and correctly suppress one that is already filtered.

The rendered assets are in `media/`; `media/weblogic-coherence-demo.mp4` is the 1920x1080 clip (about 66 seconds, with a 3 second intro and 4 second outro card). The editable shot list and narration are in `scenario.json`.

## What the clip shows

The page evaluates each Coherence extractor class from a real WebLogic 14.1.1.0.0 GA `coherence.jar` against two default WebLogic serialization filters, the 14.1.1 GA filter and the current 15.1.1 filter. Two real GadgetHunter components produce every value on screen:

- `tools.analysis.deserialization_filter.decide()` gives the per-class allow or deny decision that the target's serial filter makes during `resolveClass`.
- `scan_rules.inventory`, the same bytecode reader the Stage 1 scanner uses, reads the reflective sink reachable inside each extractor's deserialization-reachable method.

The headline row is `com.tangosol.util.extractor.UniversalExtractor`. Its `extract` method resolves a method by name from the deserialized extractor's own fields and calls `java.lang.reflect.Method.invoke`. That class **passes** the 14.1.1 GA default filter and is **denied** on 15.1.1, where Oracle added it to the blacklist after the 14.1.1 release. It is the gadget behind CVE-2020-2883 and CVE-2020-14756. `ReflectionExtractor` (CVE-2020-2555) is denied on both builds, so the clip also shows the tool suppressing a path that the filter already blocks.

## Scope

These are known, already-patched CVEs. The clip validates GadgetHunter's detection against ground truth on an unpatched build. It is not a 0-day, and the analysis evaluates reachability and the filter decision only. It does not construct or execute a payload. The `passes` verdict reflects that a blacklist-only filter does not deny the class; it is not a proof of exploitability.

## Provenance of the inputs

The 14.1.1 GA artifacts were extracted from the Oracle installer bundle `fmw_14.1.1.0.0_wls_lite_generic.jar` (dated 2020-03-28, before the April 2020 CPU). The product jars are nested inside the installer's component archives:

- `coherence.jar`: `Disk1/stage/Components/oracle.coherence/14.1.1.0.0/DataFiles/filegroup1.jar` -> `lib/coherence.jar`.
- The filter class `weblogic.utils.io.oif.WebLogicFilterConfig` (dated 2020-03-16): inside the `oracle.wls.core.app.server` component module `com.bea.core.utils.jar`.

The two filters in `filters/` are JEP 290 pattern strings transcribed from each build's `WebLogicFilterConfig` default. The 14.1.1 GA filter is blacklist only (deny patterns plus `maxdepth=100`, no package allowlist) and its blacklist ends at `ReflectionExtractor`.

The Oracle jars are not committed. `evidence.json` captures the generated result, so the page renders without the jar present.

## Reproduce

Regenerate the evidence from the real modules and the real jar:

```sh
python3 demos/weblogic-coherence/gen_evidence.py \
  --coherence /path/to/coherence-14.1.1.jar \
  --filter-1411 demos/weblogic-coherence/filters/weblogic-14.1.1-ga.filter \
  --filter-1511 demos/weblogic-coherence/filters/weblogic-15.1.1.filter \
  --output demos/weblogic-coherence/evidence.json
```

Record the clip. Serve the page, then narrate, record and render:

```sh
python3 -m http.server 8899 --directory demos/weblogic-coherence &

python3 demos/weblogic-coherence/build.py narrate       # OpenAI TTS -> audio (needs OPENAI_API_KEY)
python3 demos/weblogic-coherence/build.py record --dry   # check every selector, no capture
python3 demos/weblogic-coherence/build.py record         # capture frames
.gadgethunter/tools/demo-venv/bin/python \
  demos/weblogic-coherence/render_wl.py \
  .gadgethunter/demo/weblogic-recording demos/weblogic-coherence/media
```

The recording tooling is the same local demo-video skill used by `demos/workbench` (Playwright capture, OpenAI `gpt-4o-mini-tts` voice `marin`, Pillow and FFmpeg compositing). Only narration text is sent to the speech API; keys stay in the environment. The capture directory is under the ignored `.gadgethunter/` tree.

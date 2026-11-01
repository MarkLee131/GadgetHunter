# Narrated workbench walkthrough

The published assets live in `site/media/`; `site/index.html#demo` embeds the MP4.
The editable shot list and narration are in `scenario.json`.

## What the recording shows

- The actual local workbench, captured with Playwright at 1280 × 680 with 1.5× device scaling; the finished video is 1920 × 1080, 30 fps.
- A real 90-second static scan of `tests/fixtures/taint/EffectProbe.java`, compiled for Java 8, with the fair collector and automatic profiles. The recorded run retained 2,729 candidates in 512 clusters and reported **partial** coverage. Counts depend on the runtime and search budget, and are not vulnerability counts.
- The source-analysis upload form, followed by importing a **separate saved harmless validation report**. The narration explicitly identifies the switch. The video does not depict a new live model-analysis run.
- Verdict filtering, call-chain and constraint inspection, source expansion, and JSON export.

The saved validation evidence came from the local workbench run of 2026-10-31 using `demo.Example`, which forwards an object to `System.out.println`. Its report is preserved here with only `scan_identity` removed. It is a UI walkthrough fixture, not a deserialization exploit or a benchmark claim. It should not be used as a current-engine regression oracle.

Narration uses OpenAI `gpt-4o-mini-tts`, voice `marin`. Only narration text is sent to the speech API. Keys are read from `OPENAI_API_KEY`; they are never placed in a scenario or generated asset.

## Tools and attribution

Recording and speech helpers use the [Hmache/demo Agent Skill](https://github.com/Hmache/demo/tree/c78aa32fbcf3ca43522bde25d650c40233ee8284), licensed MIT, copyright 2026 Hmache. Its source and license stay together in the ignored local tool directory. `record.py` adds file uploads and optional scene preparation before narration to a generated local copy of the recorder.

`render.py` is the project-specific compositor. It uses Pillow for chapter titles, captions and cards because the local FFmpeg build does not include libass/drawtext. The video contains baked-in captions; WebVTT and SRT files are also provided. Generated audio is cached by narration text and voice settings.

## Reproduce

Run from the repository root. Requirements: Node.js, Python 3.10+, FFmpeg/FFprobe with libx264/AAC, JDK 17+ to run Flash, and a target Java runtime. The captured run used Corretto 8. Install the main project dependencies as described in the root README.

Prepare local media tooling once:

```sh
git clone https://github.com/Hmache/demo.git .gadgethunter/tools/demo-video
git -C .gadgethunter/tools/demo-video checkout c78aa32fbcf3ca43522bde25d650c40233ee8284
npm install --prefix .gadgethunter/tools/demo-video playwright@1.64.1
python3 -m venv .gadgethunter/tools/demo-venv
.gadgethunter/tools/demo-venv/bin/python -m pip install pillow
```

Install the Chromium revision required by Playwright from the tool directory with `npx playwright install chromium`, or set `CHROMIUM_PATH` to an existing compatible Chromium executable. SF Pro is used when available on macOS; Arial or DejaVu Sans is the fallback for text rendering.

In one terminal, start an isolated local workbench:

```sh
.venv/bin/python workbench.py --port 8876 \
  --data-dir .gadgethunter/demo/jobs \
  --java-home /path/to/target-jdk --collector fair
```

In another terminal, with `OPENAI_API_KEY` already set in the environment:

```sh
python3 demos/workbench/prepare.py
python3 demos/workbench/narrate.py
python3 demos/workbench/record.py --dry
python3 demos/workbench/record.py
.gadgethunter/tools/demo-venv/bin/python demos/workbench/render.py \
  .gadgethunter/demo/recording site/media
.gadgethunter/tools/demo-venv/bin/python .gadgethunter/tools/demo-video/check.py \
  .gadgethunter/demo/recording site/media/gadgethunter-demo.mp4
```

Inspect `.gadgethunter/demo/recording/review.png` and the sync report before publishing. Review early, middle and late frames within scenes as well: the upstream contact sheet samples just one second into each scene, which can still show a transition. `--dry` exercises imports and the browser's report download but does not submit a new analysis or candidate scan.

The captured script expects a completed candidate job named `Static-analysis fixture · candidate scan`, prepared by `prepare.py`. The two recording inputs (candidate archive and harmless validation source/report) are intentionally separate.

Preview with `python3 -m http.server 8877 --directory site`, then open `http://localhost:8877/#demo`. The existing GitHub Pages workflow deploys `site/` when its changes are pushed to `modern-scanning`.

## UI verification

The frontend follows the neutral surfaces, SF typography and action-blue tokens in the project's Apple design reference. Tasks lead the overview. Candidate/source analysis use separate form views. Advanced settings are collapsed, while invalid settings reveal themselves for correction. Results prioritize the verdict and 14px call chain, with report metadata and raw evidence available on demand.

With the local workbench running and fixtures prepared, run from the repository root:

```sh
node demos/workbench/verify-forms.cjs
node demos/workbench/verify-polling.cjs
node demos/workbench/verify-workbench.cjs
node demos/workbench/verify-video.cjs  # Requires the site preview on port 8877
```

Set `CHROMIUM_PATH` if using an existing browser instead of Playwright's default. These checks cover form switching and payloads, invalid-field recovery, polling/disclosure/focus preservation, candidate-to-source handoff, importing/filtering/exporting, hosted report mode, and desktop/mobile layout. API writes are intercepted during form tests; these checks do not start paid model analyses.

## Delivered build verification

The updated MP4 is 112.898 seconds, 1920 × 1080 at 30 fps, H.264 video with AAC audio, 6,977,610 bytes. Narration is unchanged and reused from the verified audio cache. The recording is new, using the revised UI; framing and title cards use neutral backgrounds and blue accents.

The independent frontend review found a polling/disclosure regression; the fix preserves open details on the same chain, skips unchanged result rendering and retains job-action keyboard focus. The regression checks passed. The existing workbench unittest suite ran 14 tests: 13 passed and one was skipped for Java backend prerequisites.

Full FFmpeg decoding, desktop/mobile player playback, caption loading and representative frame inspection are checked before deployment. The upstream voice checker does not detect the first onset because its silence threshold exceeds the clip's initial silence; all later scene offsets are approximately 0.09–0.13 seconds. The same cached first narration was already independently checked at 3.146 seconds after the 3-second title.

The webpage and media publish to https://marklee131.github.io/GadgetHunter/#demo. Application-engine code is outside this UI change.

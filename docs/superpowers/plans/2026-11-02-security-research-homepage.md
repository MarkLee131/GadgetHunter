# Research homepage implementation plan

**Goal:** Implement the supplied design critique and restore the WebLogic demo to the homepage.
**Architecture:** Buildless page, stylesheet and small progressive-enhancement script. Publishable evidence and media live under `site/`.
**Tech stack:** HTML, CSS, JavaScript; existing GitHub Pages workflow.
**Spec:** `docs/superpowers/specs/2026-11-02-security-research-homepage-design.md`

## Tasks
- [x] Extract an attributable subset of the recorded fixture scan, preserving actual ranks and overlapping classifications.
- [x] Replace the landing-page layout with triage evidence, pipeline, benchmark table and explicit research/current distinction.
- [x] Publish both existing videos with poster, captions, transcript and source links; document WebLogic asset synchronization.
- [x] Check responsive rendering, keyboard/selection/copy behavior, local assets and evidence references.

## Review focus
Partial coverage must stay visible. Novel does not mean a confirmed vulnerability. Blocked and known can overlap. No synthetic SAT/confidence data. The WebLogic video must be inside the Pages publication root. Preserve the workbench video and its separate saved-report disclosure.

## Verification record

- Browser: local headless Chrome, using the existing Playwright installation because no in-app browser connection was available.
- Actual playback succeeded for both 1080p H.264/AAC videos (workbench 127.76s, WebLogic 65.80s), each with one caption track.
- Candidate selection, keyboard activation, accessible result announcements, clipboard success and denial fallback, evidence-load failure and fragment links checked.
- No horizontal overflow at 320, 390, 768, 1024 or 1440 pixels; desktop and mobile screenshots inspected.
- Published asset paths checked; WebLogic media and evidence match originals byte-for-byte. Triage fields match recorded source output.
- Independent review corrected the 197-chain citation to Figure 5 and added accessible candidate announcements.
- JavaScript syntax, whitespace checks and repository design-skill validation passed.
- These checks validate the local implementation. Publication is verified separately through the GitHub Pages workflow for the pushed commit.

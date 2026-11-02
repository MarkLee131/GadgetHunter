#!/usr/bin/env python3
"""Narrate and record the WebLogic Coherence filter-rediscovery clip.

Reuses the same local demo-video tooling as demos/workbench, but for this
scenario and its own recording directory. Serve the page first:

    python3 -m http.server 8899 --directory demos/weblogic-coherence

Then:

    python3 demos/weblogic-coherence/build.py narrate   # OpenAI TTS -> audio
    python3 demos/weblogic-coherence/build.py record --dry   # check selectors, no capture
    python3 demos/weblogic-coherence/build.py record         # capture frames

OPENAI_API_KEY must be set for narration. The key stays in the environment.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / "demos/weblogic-coherence"
TOOL = ROOT / ".gadgethunter/tools/demo-video"
OUT = ROOT / ".gadgethunter/demo/weblogic-recording"
SCENARIO = HERE / "scenario.json"
sys.path.insert(0, str(TOOL))


def narrate():
    import tts
    scenario = json.loads(SCENARIO.read_text())
    (OUT / "audio").mkdir(parents=True, exist_ok=True)
    fp_path = OUT / "narration-cache.json"
    fingerprints = json.loads(fp_path.read_text()) if fp_path.exists() else {}
    durations = {}
    new_fp = {}
    for i, step in enumerate(scenario["steps"]):
        fingerprint = hashlib.sha256(json.dumps([step["say"], scenario["voice"]], sort_keys=True).encode()).hexdigest()
        dst = OUT / "audio" / f"step_{i:02d}.wav"
        if not dst.exists() or fingerprints.get(str(i)) != fingerprint:
            raw = tts.synth(step["say"], scenario["voice"], str(OUT / "audio" / f"raw_{i:02d}"))
            tts.polish(raw, str(dst))
            os.remove(raw)
        seconds = round(tts.duration(str(dst)), 3)
        durations[str(i)] = seconds
        new_fp[str(i)] = fingerprint
        print(f"Scene {i}: {seconds:.3f}s  {step['label']}", flush=True)
    (OUT / "durations.json").write_text(json.dumps(durations, indent=2))
    fp_path.write_text(json.dumps(new_fp, indent=2))
    (OUT / "scenario.json").write_text(json.dumps(scenario, indent=2))


def patched_recorder():
    source = (TOOL / "record.js").read_text()
    if "case 'upload':" not in source:
        anchor = "      case 'fill':"
        source = source.replace(anchor, "      case 'upload': { await page.locator(a.selector).setInputFiles(a.files); await sleep(400); break; }\n" + anchor, 1)
    if "for (const a of s.before || [])" not in source:
        anchor = "      const s = scenario.steps[i];"
        source = source.replace(anchor, anchor + "\n      for (const a of s.before || []) await run(a);", 1)
    recorder = TOOL / "gadgethunter-record.js"
    recorder.write_text(source)
    return recorder


def record(extra):
    recorder = patched_recorder()
    OUT.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    # Pin the Chromium that is actually installed in the Playwright cache.
    cache = Path.home() / "Library/Caches/ms-playwright"
    cand = list(cache.glob("chromium-*/chrome-mac*/*/Contents/MacOS/*")) if cache.exists() else []
    if cand and not env.get("CHROMIUM_PATH"):
        env["CHROMIUM_PATH"] = str(cand[0])
    subprocess.run(["node", str(recorder), str(SCENARIO), str(OUT), *extra], cwd=ROOT, check=True, env=env)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "all"
    if cmd == "narrate":
        narrate()
    elif cmd == "record":
        record(sys.argv[2:])
    elif cmd == "all":
        narrate()
        record([])
    else:
        print(__doc__)
        sys.exit(2)

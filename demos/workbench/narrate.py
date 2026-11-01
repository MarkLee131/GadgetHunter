#!/usr/bin/env python3
"""Generate scene audio with the local demo-video skill; key stays in the environment."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / '.gadgethunter/tools/demo-video'))
import tts


def main():
    scenario = json.loads((ROOT / 'demos/workbench/scenario.json').read_text())
    out = ROOT / '.gadgethunter/demo/recording'
    (out / 'audio').mkdir(parents=True, exist_ok=True)
    fingerprints_path = out / 'narration-cache.json'
    fingerprints = json.loads(fingerprints_path.read_text()) if fingerprints_path.exists() else {}

    def make(pair):
        i, step = pair
        fingerprint = hashlib.sha256(json.dumps([step['say'], scenario['voice']], sort_keys=True).encode()).hexdigest()
        dst = out / 'audio' / f'step_{i:02d}.wav'
        if not dst.exists() or fingerprints.get(str(i)) != fingerprint:
            raw = tts.synth(step['say'], scenario['voice'], str(out / 'audio' / f'raw_{i:02d}'))
            tts.polish(raw, str(dst))
            os.remove(raw)
        seconds = round(tts.duration(str(dst)), 3)
        print(f'Scene {i}: {seconds:.3f}s', flush=True)
        return str(i), seconds, fingerprint

    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(make, enumerate(scenario['steps'])))
    (out / 'durations.json').write_text(json.dumps({i: s for i, s, _ in results}, indent=2))
    fingerprints_path.write_text(json.dumps({i: fp for i, _, fp in results}, indent=2))
    (out / 'scenario.json').write_text(json.dumps(scenario, indent=2))


if __name__ == '__main__':
    main()

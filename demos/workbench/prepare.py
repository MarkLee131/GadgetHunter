#!/usr/bin/env python3
"""Prepare the documented fixtures and run one real, bounded candidate scan.

Start the workbench on port 8876 first (see README). No fixture is executed.
"""
import base64
import json
from pathlib import Path
import shutil
import subprocess
import time
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / '.gadgethunter/demo/fixture'
API = 'http://127.0.0.1:8876/api'
NAME = 'Static-analysis fixture · candidate scan'


def request(path, data=None):
    headers = {'Content-Type': 'application/json', 'X-GadgetHunter': '1'}
    req = urllib.request.Request(API + path, headers=headers,
                                 data=json.dumps(data).encode() if data is not None else None)
    with urllib.request.urlopen(req, timeout=20) as response:
        return json.load(response)


def main():
    classes = FIXTURE / 'classes'
    classes.mkdir(parents=True, exist_ok=True)
    subprocess.run(['javac', '--release', '8', '-d', str(classes), str(ROOT / 'tests/fixtures/taint/EffectProbe.java')], check=True)
    archive = FIXTURE / 'static-analysis-fixture.jar'
    subprocess.run(['jar', 'cf', str(archive), '-C', str(classes), '.'], check=True)
    source = ROOT / 'demos/workbench/fixtures'
    for name in ['validation-chains.txt', 'saved-validation-report.json']:
        shutil.copyfile(source / name, FIXTURE / name)
    with zipfile.ZipFile(FIXTURE / 'validation-sources.zip', 'w') as bundle:
        bundle.write(source / 'Example.java', 'demo/Example.java')
    jobs = request('/jobs')
    job = next((j for j in jobs if j['name'] == NAME and j.get('candidate_count', 0) > 0
                and j['status'] not in ('queued', 'running', 'cancelling')), None)
    if job:
        print('Using existing real scan:', job['id'], job['candidate_count'], 'candidates')
        return
    job = request('/candidate-jobs', {
        'name': NAME, 'apps': [{'name': archive.name, 'data': base64.b64encode(archive.read_bytes()).decode()}],
        'libraries': [], 'search_seconds': 90, 'heap_mb': 4096, 'enhancement': 'none', 'profiles': ['auto'],
    })
    print('Scanning static fixture:', job['id'], flush=True)
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        job = next(j for j in request('/jobs') if j['id'] == job['id'])
        if job['status'] not in ('queued', 'running', 'cancelling'):
            print(job['status'], job.get('candidate_count', 0), 'candidates')
            if not job.get('candidate_count'):
                raise RuntimeError('No candidates retained. Inspect the scan details before recording.')
            return
        time.sleep(3)
    raise TimeoutError('Scan is still active. Inspect the workbench before recording.')


if __name__ == '__main__':
    main()

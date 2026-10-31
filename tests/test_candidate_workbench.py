import base64
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.request
import zipfile
from http.server import ThreadingHTTPServer

from prepare_scan import prepare
from scan_rules.workbench import execute_candidate_job, candidate_details
from workbench import Handler, Jobs, save_jars
import yaml

ROOT = Path(__file__).resolve().parents[1]
EDGE = '[VIRTUAL] <Example: java.lang.Object readResolve()> --(line:1, constraint:[0])--> <Target: java.lang.Object read()>'
OTHER = EDGE.replace('line:1', 'line:2')


def encoded_archive(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return base64.b64encode(buffer.getvalue()).decode()


class CandidateWorkbenchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        runtime = self.folder / 'jdk8/lib'
        runtime.mkdir(parents=True)
        (runtime / 'rt.jar').write_bytes(b'fixture runtime; workers are mocked in these unit tests')
        self.runtime = runtime.parent

    def payload(self):
        return {'name': 'Candidate fixture', 'apps': [{'name': 'target.jar', 'data': encoded_archive({'A.class': b'fixture'})}]}

    def test_candidates_require_runtime_but_not_api_key(self):
        jobs = Jobs(self.folder / 'jobs', java8_home=self.runtime, collector='fair', profiles=['native-core', 'reflection-boundaries'])
        self.addCleanup(jobs.close)
        with patch.dict(os.environ, {'OPENAI_API_KEY': ''}), patch.object(jobs.executor, 'submit'):
            record = jobs.submit_candidates(self.payload())
            self.assertEqual(record['kind'], 'candidate')
            self.assertEqual(record['enhancement'], 'none')
            self.assertEqual(record['collector'], 'fair')
            self.assertEqual(record['profiles'], ['native-core', 'reflection-boundaries'])
            self.assertTrue((jobs.directory / record['id'] / record['apps'][0]).is_file())
            with self.assertRaisesRegex(ValueError, 'OPENAI_API_KEY'):
                jobs.submit_candidates(dict(self.payload(), enhancement='llm'))
        disabled = Jobs(self.folder / 'disabled')
        self.addCleanup(disabled.close)
        with self.assertRaisesRegex(ValueError, 'java8-home'):
            disabled.submit_candidates(self.payload())

    def test_upload_validation_and_queue_limits_leave_no_partial_jobs(self):
        jobs = Jobs(self.folder / 'jobs', java8_home=self.runtime)
        self.addCleanup(jobs.close)
        invalid = [{'apps': []}, {'apps': [{'name': '../x.jar', 'data': 'bad'}]},
                   {'apps': [{'name': 'x.jar', 'data': base64.b64encode(b'not an archive').decode()}]},
                   dict(self.payload(), heap_mb=True), dict(self.payload(), search_seconds=1801)]
        for payload in invalid:
            with self.assertRaises(ValueError):
                jobs.submit_candidates(payload)
        self.assertEqual(list(jobs.directory.glob('*/job.json')), [])
        with patch.object(jobs.executor, 'submit'):
            for _ in range(8):
                jobs.submit_candidates(self.payload())
            with self.assertRaisesRegex(ValueError, 'queue is full'):
                jobs.submit_candidates(self.payload())

    def test_retry_creates_fresh_job_and_analysis_keeps_parent_coverage(self):
        jobs = Jobs(self.folder / 'jobs', java8_home=self.runtime)
        self.addCleanup(jobs.close)
        with patch.object(jobs.executor, 'submit'), patch.dict(os.environ, {'OPENAI_API_KEY': 'test-key'}):
            original = jobs.submit_candidates(self.payload())
            job_id = original['id']
            jobs.records[job_id].update(status='partial', candidate_count=1)
            (jobs.directory / job_id / 'chains').write_text(EDGE + '\n\n')
            with self.assertRaisesRegex(ValueError, 'cannot resume'):
                jobs.action(job_id, 'resume')
            retried = jobs.action(job_id, 'retry')
            self.assertNotEqual(retried['id'], job_id)
            self.assertFalse((jobs.directory / retried['id'] / 'chains').exists())
            self.assertEqual((jobs.directory / job_id / 'chains').read_text(), EDGE + '\n\n')
            analysis = jobs.submit({'candidate_job_id': job_id, 'sources_zip': encoded_archive({'Example.java': 'class Example {}'})})
            self.assertEqual(analysis['candidate_job_id'], job_id)
            self.assertEqual(analysis['candidate_coverage'], 'partial')
            self.assertEqual(analysis['chain_count'], 1)
            output = jobs.directory / analysis['id'] / 'output/run'
            result_dir = output / 'chain0/analysis_results'
            result_dir.mkdir(parents=True)
            (output / 'scan.json').write_text('{}')
            (result_dir / 'analysis_result_chain0.json').write_text(json.dumps({'chain_id': 0}))
            exported = jobs.results(analysis['id'])[0]['candidate_generation']
            self.assertEqual(exported['status'], 'partial')
            self.assertFalse(exported['exhaustive'])

    def test_candidate_cancellation_is_forwarded_to_running_worker(self):
        jobs = Jobs(self.folder / 'jobs', java8_home=self.runtime)
        self.addCleanup(jobs.close)
        with patch.object(jobs.executor, 'submit'):
            record = jobs.submit_candidates(self.payload())
        job_id = record['id']
        jobs.records[job_id]['status'] = 'running'
        event = jobs.cancellations[job_id] = threading.Event()
        self.assertEqual(jobs.action(job_id, 'cancel')['status'], 'cancelling')
        self.assertTrue(event.is_set())
        jobs.cancellations.pop(job_id)

    def test_worker_merges_phases_and_keeps_baseline_on_enhancement_failure(self):
        record = dict(apps=[], libraries=[], search_seconds=5, heap_mb=512, enhancement='deterministic', model='gpt-4.1', collector='fair', profiles=['native-core', 'reflection-boundaries'])
        def scan(path, **kwargs):
            self.assertEqual(kwargs['collector'], 'fair')
            path.mkdir(exist_ok=True)
            chains = [EDGE] if path.name == 'baseline' else [EDGE, OTHER]
            (path / 'chains').write_text(''.join(chain + '\n\n' for chain in chains))
            return dict(status='completed', candidate_count=len(chains))
        def prepare_fixture(apps, libraries, home, path, profiles):
            self.assertEqual(profiles, record['profiles'])
            path.mkdir()
        for fail in (False, True):
            folder = self.folder / str(fail)
            folder.mkdir()
            with patch('scan_rules.workbench.prepare', side_effect=prepare_fixture), \
                 patch('scan_rules.workbench.run_backend', side_effect=scan), \
                 patch('scan_rules.workbench.enhance', side_effect=ValueError('proposal failure') if fail else None):
                result = execute_candidate_job(folder, record, java8_home='fixture', java='java', cancel=threading.Event(), update=lambda *_: None)
            self.assertEqual(result['status'], 'partial' if fail else 'completed')
            self.assertEqual(result['candidate_count'], 1 if fail else 2)
            provenance = json.loads((folder / 'candidate-index.json').read_text())
            self.assertEqual(provenance[0]['phases'], ['baseline'] if fail else ['baseline', 'enhanced'])
            self.assertIn(EDGE, (folder / 'chains').read_text())

    def test_cancelled_before_preparation_never_launches_backend(self):
        event = threading.Event()
        event.set()
        with patch('scan_rules.workbench.prepare') as prepare_mock, patch('scan_rules.workbench.run_backend') as backend:
            result = execute_candidate_job(self.folder, {'enhancement': 'none'}, java8_home='unused', java='java', cancel=event, update=lambda *_: None)
        prepare_mock.assert_not_called()
        backend.assert_not_called()
        self.assertEqual(result['status'], 'cancelled')


@unittest.skipUnless(os.environ.get('GADGETHUNTER_TEST_JAVA8_HOME') and os.environ.get('GADGETHUNTER_TEST_HTTP') == '1' and shutil.which('javac'),
                     'Set Java 8 home and GADGETHUNTER_TEST_HTTP=1 for real local HTTP/backend integration')
class CandidateHTTPIntegrationTests(unittest.TestCase):
    def test_jar_upload_search_coverage_export_and_analysis_handoff(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            classes = folder / 'classes'
            classes.mkdir()
            subprocess.run(['javac', '--release', '8', '-d', str(classes), str(ROOT / 'tests/fixtures/taint/Wrappers.java')], check=True, capture_output=True)
            upload = encoded_archive({str(p.relative_to(classes)): p.read_bytes() for p in classes.rglob('*.class')})
            jobs = Jobs(folder / 'jobs', java8_home=os.environ['GADGETHUNTER_TEST_JAVA8_HOME'], collector='fair')
            self.addCleanup(jobs.close)
            server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            server.jobs = jobs
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            base = f'http://127.0.0.1:{server.server_port}'
            def request(path, data=None):
                headers = {'Content-Type': 'application/json', 'X-GadgetHunter': '1', 'Origin': base}
                req = urllib.request.Request(base + path, data=json.dumps(data).encode() if data is not None else None, headers=headers)
                with urllib.request.urlopen(req, timeout=10) as response:
                    body = response.read()
                    return json.loads(body) if 'application/json' in response.headers['Content-Type'] else body.decode()
            def scoped_prepare(*args):
                result = prepare(*args)
                config_path = Path(args[3]) / 'config.yml'
                config = yaml.safe_load(config_path.read_text())
                config['sources'] = [s for s in config['sources'] if s.startswith('<fixtures.')]
                config['SINK_MAX_TIME'] = 5
                config_path.write_text(yaml.safe_dump(config))
                return result
            with patch('scan_rules.workbench.prepare', side_effect=scoped_prepare), patch.dict(os.environ, {'OPENAI_API_KEY': ''}):
                self.assertTrue(request('/api/health')['candidate_configured'])
                self.assertFalse(request('/api/health')['api_configured'])
                job = request('/api/candidate-jobs', {'name': 'HTTP integration', 'apps': [{'name': 'fixture.jar', 'data': upload}],
                                                      'enhancement': 'deterministic', 'search_seconds': 45, 'heap_mb': 1024})
                deadline = time.monotonic() + 70
                while True:
                    current = next(r for r in request('/api/jobs') if r['id'] == job['id'])
                    if current['status'] not in ('queued', 'running', 'cancelling'):
                        break
                    self.assertLess(time.monotonic(), deadline, current)
                    time.sleep(0.25)
                self.assertEqual(current['status'], 'completed', current)
                self.assertGreaterEqual(current['candidate_count'], 2)
                details = request(f"/api/jobs/{job['id']}/candidate-report")
                self.assertEqual(details['enhancement']['accepted_rules'], 4)
                self.assertEqual(len(details['phases']), 2)
                self.assertFalse(details['phases'][0]['execution']['coverage']['exhaustive'])
                for phase in details['phases']:
                    self.assertEqual(phase['execution']['collector']['status'], 'completed')
                    self.assertEqual(phase['execution']['collector_errors'], [])
                chains = request(f"/api/jobs/{job['id']}/chains")
                self.assertIn('<fixtures.WrappedRead:', chains)
                self.assertIn('<fixtures.WrappedEffect:', chains)
            with patch.object(jobs.executor, 'submit'), patch.dict(os.environ, {'OPENAI_API_KEY': 'test-key'}):
                analysis = request('/api/jobs', {'candidate_job_id': job['id'], 'sources_zip': encoded_archive({'Wrappers.java': (ROOT / 'tests/fixtures/taint/Wrappers.java').read_text()})})
                self.assertEqual(analysis['candidate_job_id'], job['id'])
                self.assertEqual(analysis['chain_count'], current['candidate_count'])
                self.assertFalse(analysis['candidate_generation']['exhaustive'])
                self.assertEqual(len(analysis['candidate_generation']['phases']), 2)
                self.assertTrue(analysis['candidate_generation']['phases'][0]['knowledge_sha256'])
                self.assertTrue((jobs.directory / analysis['id'] / 'candidate-index.json').exists())
                self.assertEqual(request(f"/api/jobs/{analysis['id']}/cancel", {})['status'], 'cancelled')

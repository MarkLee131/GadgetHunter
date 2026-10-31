#!/usr/bin/env python3
"""Local GadgetHunter workbench. Run: python workbench.py"""
import argparse
import base64
import binascii
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import shutil
import stat
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'multi-agents'))
from tools.analysis.scan_session import atomic_json
from tools.analysis.chain_parser import validate_chain_file
from prepare_scan import PROFILES

MAX_REQUEST = 32 * 1024 * 1024
CANDIDATE_REQUEST = 360 * 1024 * 1024
MAX_EXPANDED = 128 * 1024 * 1024


def save_jars(data, folder):
    apps, libraries = data.get('apps'), data.get('libraries', [])
    if not isinstance(apps, list) or not apps or not isinstance(libraries, list) or len(apps) + len(libraries) > 64:
        raise ValueError('Choose at least one application JAR and at most 64 JARs in total.')
    (folder / 'inputs').mkdir()
    paths, labels, total = {'apps': [], 'libraries': []}, [], 0
    for kind, files in (('apps', apps), ('libraries', libraries)):
        for index, entry in enumerate(files):
            if not isinstance(entry, dict):
                raise ValueError('Invalid JAR upload.')
            name = entry.get('name')
            if not isinstance(name, str) or not 1 <= len(name) <= 200 or not name.lower().endswith(('.jar', '.war')) or '/' in name or '\\' in name:
                raise ValueError('Upload JAR or WAR files using plain filenames.')
            try:
                encoded = entry.get('data')
                if not isinstance(encoded, str) or len(encoded) > 350 * 1024 * 1024:
                    raise ValueError('Oversized JAR upload.')
                content = base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise ValueError('Invalid or oversized JAR encoding.') from exc
            total += len(content)
            if len(content) > 256 * 1024 * 1024 or total > 256 * 1024 * 1024:
                raise ValueError('Uploaded archives must be at most 256 MiB combined.')
            if not zipfile.is_zipfile(io.BytesIO(content)):
                raise ValueError(f'{name} is not a valid JAR archive.')
            relative = f'inputs/{kind}-{index:03d}.jar'
            (folder / relative).write_bytes(content)
            paths[kind].append(relative)
            labels.append({'kind': kind, 'name': name, 'bytes': len(content)})
    return paths, labels


def extract_sources(encoded, destination):
    """Extract Java source only, with traversal, symlink, and expansion limits."""
    try:
        content = base64.b64decode(encoded, validate=True)
        archive = zipfile.ZipFile(io.BytesIO(content))
    except (ValueError, TypeError, binascii.Error, zipfile.BadZipFile) as exc:
        raise ValueError('Choose a valid ZIP containing Java sources.') from exc
    total = count = 0
    with archive:
        if len(archive.infolist()) > 10000:
            raise ValueError('Source archive contains too many entries (maximum 10,000).')
        for entry in archive.infolist():
            path = PurePosixPath(entry.filename)
            if path.is_absolute() or '..' in path.parts or '\\' in entry.filename or stat.S_ISLNK(entry.external_attr >> 16):
                raise ValueError('Source archive contains an unsafe path or symbolic link.')
            total += entry.file_size
            if total > MAX_EXPANDED:
                raise ValueError('Expanded archive exceeds 128 MiB.')
            if entry.is_dir() or path.suffix != '.java':
                continue
            if entry.file_size > 4 * 1024 * 1024:
                raise ValueError('An individual source file exceeds 4 MiB.')
            target = destination.joinpath(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(entry) as source, target.open('xb') as out:
                data = source.read(entry.file_size + 1)
                if len(data) != entry.file_size:
                    raise ValueError('Invalid source entry size.')
                out.write(data)
            count += 1
    if not count:
        raise ValueError('The archive contains no .java source files.')
    return count


class Jobs:
    def __init__(self, directory, timeout=1800, *, java8_home=None, java='java', backend='auto', collector='stock', profiles=None):
        self.java8_home = str(Path(java8_home).expanduser().resolve(strict=True)) if java8_home else None
        self.java = java
        if backend not in ('auto', 'stock', 'optimized'):
            raise ValueError('Backend must be auto, stock, or optimized.')
        self.backend = backend
        if collector not in ('stock', 'fair') or (collector == 'fair' and backend == 'stock'):
            raise ValueError('Collector must be stock or fair; fair requires backend auto or optimized.')
        self.collector = collector
        self.profiles = list(profiles) if profiles is not None else ['auto']
        if self.profiles != ['auto'] and (not self.profiles or any(profile not in PROFILES for profile in self.profiles)):
            raise ValueError('Select supported built-in profiles.')
        if {'reflection-dispatch', 'reflection-boundaries'} <= set(self.profiles):
            raise ValueError('Reflection dispatch and boundaries cannot be combined in one search.')
        if self.java8_home and not any((Path(self.java8_home) / p).is_file() for p in ('jre/lib/rt.jar', 'lib/rt.jar')):
            raise ValueError('The target Java 8 runtime must contain jre/lib/rt.jar or lib/rt.jar.')
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        import fcntl
        self.lease = (self.directory / '.workbench.lock').open('a')
        try:
            fcntl.flock(self.lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.lease.close()
            raise ValueError('Another workbench is using this data directory.')
        self.timeout = timeout
        self.lock = threading.RLock()
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='gadgethunter')
        self.records, self.processes, self.cancellations = {}, {}, {}
        for path in self.directory.glob('*/job.json'):
            try:
                record = json.loads(path.read_text())
                if record['status'] in ('running', 'queued', 'cancelling'):
                    message = ('Workbench restarted; run again to start a fresh candidate search.'
                               if record.get('kind') == 'candidate' else 'Workbench restarted; resume to continue.')
                    record.update(status='interrupted', message=message)
                    atomic_json(path, record)
                self.records[record['id']] = record
            except (ValueError, KeyError, OSError):
                continue

    def _save(self, record):
        atomic_json(self.directory / record['id'] / 'job.json', record)

    def _check_queue(self):
        if sum(r['status'] in ('running', 'queued', 'cancelling') for r in self.records.values()) >= 8:
            raise ValueError('The queue is full (8 jobs). Wait for a scan to finish.')

    def submit_candidates(self, data):
        if not self.java8_home:
            raise ValueError('Restart workbench.py with --java8-home /path/to/target-jdk8 to enable JAR scans.')
        seconds, heap = data.get('search_seconds', 300), data.get('heap_mb', 4096)
        mode, model = data.get('enhancement', 'none'), str(data.get('model', 'gpt-4.1')).strip()
        if type(seconds) is not int or not 5 <= seconds <= 1800 or type(heap) is not int or not 512 <= heap <= 16384:
            raise ValueError('Use 5–1800 seconds per search and a 512–16384 MiB heap.')
        if mode not in ('none', 'deterministic', 'llm', 'llm-gaps') or not re.fullmatch(r'[A-Za-z0-9._:/-]{1,100}', model):
            raise ValueError('Invalid enhancement mode or model name.')
        if mode in ('llm', 'llm-gaps') and not os.getenv('OPENAI_API_KEY'):
            raise ValueError('LLM proposals require OPENAI_API_KEY in the server environment.')
        profiles = data.get('profiles', self.profiles)
        if profiles != ['auto'] and (not isinstance(profiles, list) or not profiles or len(profiles) > len(PROFILES)
                or any(p not in PROFILES for p in profiles) or 'native-core' not in profiles
                or {'reflection-dispatch', 'reflection-boundaries'} <= set(profiles)):
            raise ValueError('Choose auto, or native-core plus optional built-in profiles; reflection dispatch and boundaries are exclusive.')
        with self.lock:
            self._check_queue()
            job_id = uuid.uuid4().hex
            folder = self.directory / job_id
            folder.mkdir()
            try:
                paths, labels = save_jars(data, folder)
            except Exception:
                shutil.rmtree(folder)
                raise
            record = dict(id=job_id, kind='candidate', name=str(data.get('name', '')).strip()[:100] or 'JAR scan',
                          **paths, uploads=labels, search_seconds=seconds, heap_mb=heap, enhancement=mode, model=model,
                          backend=self.backend, collector=self.collector, profiles=list(dict.fromkeys(profiles)),
                          candidate_count=0, status='queued', created_at=time.time(), message='Waiting for the candidate worker.')
            self.records[job_id] = record
            self._save(record)
            self.executor.submit(self._run_candidates, job_id)
            return dict(record)

    def _run_candidates(self, job_id):
        from scan_rules.workbench import execute_candidate_job
        with self.lock:
            record = self.records[job_id]
            if record['status'] != 'queued':
                return
            record.update(status='running', started_at=time.time(), phase='preparing')
            cancel = self.cancellations[job_id] = threading.Event()
            self._save(record)

        def update(phase, message):
            with self.lock:
                record.update(phase=phase, message=message)
                self._save(record)

        try:
            result = execute_candidate_job(self.directory / job_id, record, java8_home=self.java8_home,
                                           java=self.java, cancel=cancel, update=update)
        except Exception as exc:
            result = dict(status='failed', message=f'Candidate worker failed: {type(exc).__name__}: {exc}')
        with self.lock:
            record.update(result, finished_at=time.time())
            self.cancellations.pop(job_id, None)
            self._save(record)

    def submit(self, data):
        name = str(data.get('name', '')).strip()[:100] or 'Untitled scan'
        model = str(data.get('model', 'gpt-4.1')).strip()
        limit = data.get('max_chains', 100)
        if type(limit) is not int or not 1 <= limit <= 10000:
            raise ValueError('Chain limit must be between 1 and 10,000.')
        if not re.fullmatch(r'[A-Za-z0-9._:/-]{1,100}', model):
            raise ValueError('Invalid model name.')
        chains = data.get('chains')
        parent_id = data.get('candidate_job_id')
        parent = None
        if parent_id is not None:
            if not isinstance(parent_id, str) or not re.fullmatch(r'[a-f0-9]{32}', parent_id):
                raise ValueError('Invalid candidate job ID.')
            parent = self.records.get(parent_id)
            if not parent or parent.get('kind') != 'candidate' or parent['status'] in ('running', 'queued', 'cancelling'):
                raise ValueError('Select a finished candidate job.')
            selection = data.get('selection', 'review')
            if selection not in ('review', 'ranked', 'all'):
                raise ValueError('Selection must be review, ranked or all.')
            from scan_rules.workbench import selected_chains
            chains, selected_provenance = selected_chains(self.directory / parent_id, selection)
        if not isinstance(chains, str) or not chains.strip() or len(chains.encode()) > 8 * 1024 * 1024:
            raise ValueError('Provide a nonempty candidate chains file of at most 8 MiB.')
        if not os.getenv('OPENAI_API_KEY'):
            raise ValueError('Set OPENAI_API_KEY in the workbench server environment before starting a scan.')
        with self.lock:
            self._check_queue()
            job_id = uuid.uuid4().hex
            folder = self.directory / job_id
            folder.mkdir()
            try:
                (folder / 'chains').write_text(chains, encoding='utf-8')
                validation = validate_chain_file(str(folder / 'chains'))
                if not validation['valid']:
                    raise ValueError('Candidate chains do not match the modified Flash output format.')
                source_count = extract_sources(data.get('sources_zip'), folder / 'sources')
            except Exception:
                import shutil
                shutil.rmtree(folder)
                raise
            record = dict(id=job_id, kind='analysis', name=name, model=model, max_chains=limit,
                          chain_count=validation['total_chains'], source_count=source_count,
                          status='queued', created_at=time.time(), message='Waiting for the analysis worker.')
            if parent:
                record.update(candidate_job_id=parent_id, candidate_coverage=parent['status'])
                from scan_rules.workbench import candidate_details
                parent_details = candidate_details(self.directory / parent_id)
                record['candidate_generation'] = dict(job_id=parent_id, status=parent['status'], exhaustive=False,
                    phases=[dict(name=phase['name'], **{key: (phase['execution'] or {}).get(key) for key in
                        ('status', 'config_sha256', 'knowledge_sha256', 'inventory_sha256', 'backend_sha256', 'backend_optimization')})
                        for phase in parent_details['phases']])
                record['candidate_generation']['selection'] = selection
                atomic_json(folder / 'candidate-index.json', selected_provenance)
            self.records[job_id] = record
            self._save(record)
            self.executor.submit(self._run, job_id, False)
            return dict(record)

    def _run(self, job_id, resume):
        with self.lock:
            record = self.records[job_id]
            if record['status'] != 'queued':
                return
            record.update(status='running', started_at=time.time(), message='Analyzing candidate chains.')
            self._save(record)
            folder = self.directory / job_id
            command = [sys.executable, str(ROOT / 'multi-agents/main.py'), '--batch',
                       '--chains-file', str(folder / 'chains'), '--project-root', str(folder / 'sources'),
                       '--model', record['model'], '--max-chains', str(record['max_chains']),
                       '--output-dir', str(folder / 'output')]
            run = self._run_dir(job_id)
            if resume and run is not None:
                command += ['--resume', str(run)]
            try:
                log = (folder / 'worker.log').open('ab')
                process = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                self.processes[job_id] = process
            except Exception as exc:
                if 'log' in locals():
                    log.close()
                record.update(status='failed', message=str(exc))
                self._save(record)
                return
        try:
            code = process.wait(timeout=self.timeout)
            with self.lock:
                if record['status'] == 'cancelling':
                    record.update(status='cancelled', message='Scan cancelled. Completed chain results are retained.')
                else:
                    record.update(status='completed' if code == 0 else 'needs_review' if code == 2 else 'failed',
                                  message={0: 'Analysis complete. Review candidate evidence.',
                                           2: 'Analysis finished with inconclusive findings.'}.get(code, 'Analysis stopped with an error. Review the worker log.'),
                                  exit_code=code)
        except subprocess.TimeoutExpired:
            self._terminate(process)
            with self.lock:
                record.update(status='interrupted', message='Time limit reached. Completed chains are retained; resume to continue.')
        finally:
            log.close()
            with self.lock:
                self.processes.pop(job_id, None)
                record['finished_at'] = time.time()
                self._save(record)

    @staticmethod
    def _terminate(process):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            except ProcessLookupError:
                pass

    def _run_dir(self, job_id):
        paths = sorted((self.directory / job_id / 'output').glob('*/scan.json'))
        return paths[-1].parent if paths else None

    def results(self, job_id):
        if job_id not in self.records:
            raise KeyError(job_id)
        run = self._run_dir(job_id)
        results = []
        context = self.records[job_id].get('candidate_generation')
        provenance = {}
        if context:
            from scan_rules.workbench import read_json
            entries = read_json(self.directory / job_id / 'candidate-index.json') or []
            provenance = {item['chain_id']: item for item in entries}
        if run:
            for path in run.glob('chain*/analysis_results/analysis_result_chain*.json'):
                try:
                    result = json.loads(path.read_text())
                    if context:
                        origin = provenance.get(result['chain_id'], {})
                        result['candidate_generation'] = dict(context, chain_phases=origin.get('phases', []),
                                                              source_chain_id=origin.get('source_chain_id', result['chain_id']),
                                                              triage=origin.get('triage'))
                    results.append(result)
                except (OSError, ValueError):
                    continue
        return sorted(results, key=lambda item: item['chain_id'])

    def list(self):
        from scan_rules.workbench import read_json
        with self.lock:
            records = []
            for record in sorted(self.records.values(), key=lambda r: r['created_at'], reverse=True):
                item = dict(record, completed_chains=len(self.results(record['id'])))
                if record.get('kind') == 'candidate':
                    phase = record.get('phase', 'baseline')
                    execution = read_json(self.directory / record['id'] / phase / 'stage1.json') if phase in ('baseline', 'enhanced') else None
                    item['progress'] = execution.get('progress') if execution else None
                    item['elapsed_seconds'] = execution.get('elapsed_seconds') if execution else None
                records.append(item)
            return records

    def action(self, job_id, action):
        with self.lock:
            record = self.records[job_id]
            if action == 'cancel':
                if record['status'] == 'queued':
                    record.update(status='cancelled', message='Cancelled before analysis started.')
                elif record['status'] == 'running':
                    record['status'] = 'cancelling'
                    if job_id in self.cancellations:
                        self.cancellations[job_id].set()
                    process = self.processes.get(job_id)
                    if process:
                        self._terminate(process)
                else:
                    raise ValueError('This job is not running or queued.')
            elif action == 'resume':
                if record.get('kind') == 'candidate':
                    raise ValueError('Candidate searches cannot resume the JVM graph; use Run again for a fresh job.')
                if record['status'] in ('queued', 'running', 'cancelling'):
                    raise ValueError('This job is already active.')
                self._check_queue()
                record.update(status='queued', message='Queued for resume.')
                self.executor.submit(self._run, job_id, True)
            elif action == 'retry' and record.get('kind') == 'candidate':
                if record['status'] in ('queued', 'running', 'cancelling'):
                    raise ValueError('This job is already active.')
                self._check_queue()
                if not self.java8_home:
                    raise ValueError('Configure --java8-home before running candidate scans.')
                if record['enhancement'] == 'llm' and not os.getenv('OPENAI_API_KEY'):
                    raise ValueError('LLM proposals require OPENAI_API_KEY in the server environment.')
                new_id = uuid.uuid4().hex
                source, destination = self.directory / job_id, self.directory / new_id
                try:
                    shutil.copytree(source / 'inputs', destination / 'inputs')
                except Exception:
                    shutil.rmtree(destination, ignore_errors=True)
                    raise
                fresh = {key: record[key] for key in ('name', 'kind', 'apps', 'libraries', 'uploads', 'search_seconds', 'heap_mb', 'enhancement', 'model')}
                fresh.update(id=new_id, retry_of=job_id, status='queued', candidate_count=0,
                             backend=self.backend, collector=self.collector, profiles=list(self.profiles),
                             created_at=time.time(), message='Fresh candidate search queued; earlier evidence is retained.')
                self.records[new_id] = fresh
                self._save(fresh)
                self.executor.submit(self._run_candidates, new_id)
                return dict(fresh)
            else:
                raise ValueError('Unknown action.')
            self._save(record)
            return dict(record)

    def close(self):
        with self.lock:
            for record in self.records.values():
                if record['status'] == 'queued':
                    record.update(status='interrupted', message='Workbench closed before the job started.')
                    self._save(record)
            processes = list(self.processes.values())
            for event in self.cancellations.values():
                event.set()
        for process in processes:
            self._terminate(process)
        self.executor.shutdown(wait=True, cancel_futures=True)
        self.lease.close()


class Handler(BaseHTTPRequestHandler):
    server_version = 'GadgetHunter'

    def _allowed(self):
        host = self.headers.get('Host', '')
        allowed = {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
        origin = self.headers.get('Origin')
        return host in allowed and (not origin or origin == f'http://{host}')

    def _send(self, payload, code=200, content_type='application/json'):
        body = json.dumps(payload, ensure_ascii=False).encode() if content_type == 'application/json' else payload
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._allowed():
            return self._send({'error': 'Local workbench requests only.'}, 403)
        path = self.path.split('?')[0]
        if path == '/api/health':
            return self._send(dict(mode='local', api_configured=bool(os.getenv('OPENAI_API_KEY')),
                                   candidate_configured=bool(self.server.jobs.java8_home)))
        if path == '/api/jobs':
            return self._send(self.server.jobs.list())
        match = re.fullmatch(r'/api/jobs/([a-f0-9]{32})/(results|log|chains|candidate-report)', path)
        if match:
            job_id, resource = match.groups()
            if job_id not in self.server.jobs.records:
                return self._send({'error': 'Job not found.'}, 404)
            if resource == 'results':
                return self._send(self.server.jobs.results(job_id))
            folder = self.server.jobs.directory / job_id
            record = self.server.jobs.records[job_id]
            if resource in ('chains', 'candidate-report') and record.get('kind') != 'candidate':
                return self._send({'error': 'This is not a candidate-generation job.'}, 400)
            if resource == 'candidate-report':
                from scan_rules.workbench import candidate_details
                return self._send(dict(job=dict(record), **candidate_details(folder)))
            if resource == 'chains':
                if record['status'] in ('queued', 'running', 'cancelling'):
                    return self._send({'error': 'Candidate generation is still active; export is available when it stops.'}, 409)
                if not (folder / 'chains').exists():
                    return self._send({'error': 'Candidate export is not ready yet.'}, 404)
                return self._send((folder / 'chains').read_bytes(), content_type='text/plain; charset=utf-8')
            logs = ['baseline/backend.log', 'enhanced/backend.log', 'candidate-error.txt'] if record.get('kind') == 'candidate' else ['worker.log']
            chunks = []
            for name in logs:
                log = folder / name
                if log.exists():
                    with log.open('rb') as f:
                        f.seek(max(0, log.stat().st_size - 20000))
                        chunks.append(name + '\n' + f.read().decode('utf-8', errors='replace'))
            content = '\n\n'.join(chunks)[-20000:] or 'Waiting for worker output.'
            for key in ('OPENAI_API_KEY', 'DEEPSEEK_API_KEY', 'ANTHROPIC_API_KEY'):
                secret = os.getenv(key)
                if secret:
                    content = content.replace(secret, '[redacted]')
            return self._send({'text': content})
        assets = {'/': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                  '/styles.css': ('styles.css', 'text/css; charset=utf-8')}
        if path not in assets:
            return self._send({'error': 'Not found.'}, 404)
        file, mime = assets[path]
        return self._send((ROOT / 'web/dist' / file).read_bytes(), content_type=mime)

    def do_POST(self):
        if not self._allowed() or self.headers.get('X-GadgetHunter') != '1':
            return self._send({'error': 'Same-origin workbench request required.'}, 403)
        if self.headers.get('Content-Type') != 'application/json':
            return self._send({'error': 'JSON request required.'}, 415)
        try:
            size = int(self.headers.get('Content-Length', '0'))
            limit = CANDIDATE_REQUEST if self.path == '/api/candidate-jobs' else MAX_REQUEST
            if not 0 < size <= limit:
                return self._send({'error': f'Request must be between 1 byte and {limit // (1024 * 1024)} MiB.'}, 413)
            data = json.loads(self.rfile.read(size))
            if not isinstance(data, dict):
                raise ValueError('Expected a JSON object.')
            if self.path == '/api/jobs':
                return self._send(self.server.jobs.submit(data), 201)
            if self.path == '/api/candidate-jobs':
                return self._send(self.server.jobs.submit_candidates(data), 201)
            match = re.fullmatch(r'/api/jobs/([a-f0-9]{32})/(cancel|resume|retry)', self.path)
            if match:
                return self._send(self.server.jobs.action(*match.groups()))
            return self._send({'error': 'Not found.'}, 404)
        except KeyError:
            self._send({'error': 'Job not found.'}, 404)
        except (ValueError, zipfile.BadZipFile, RuntimeError, OSError) as exc:
            self._send({'error': str(exc)}, 400)


def main():
    parser = argparse.ArgumentParser(description='GadgetHunter local deserialization workbench')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--data-dir', default=str(ROOT / '.gadgethunter/jobs'))
    parser.add_argument('--java8-home', default=os.getenv('GADGETHUNTER_JAVA8_HOME'), help='Target Java 8 runtime for browser JAR scans')
    parser.add_argument('--java', default='java', help='JDK 17+ executable used to run Flash')
    parser.add_argument('--backend', choices=('auto', 'stock', 'optimized'), default='auto')
    parser.add_argument('--collector', choices=('stock', 'fair'), default='stock')
    parser.add_argument('--profile', choices=('auto', *PROFILES), action='append', help='Built-in rule profile; default auto selects from the target bytecode')
    args = parser.parse_args()
    try:
        jobs = Jobs(args.data_dir, java8_home=args.java8_home, java=args.java, backend=args.backend, collector=args.collector, profiles=args.profile)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    try:
        server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    except OSError:
        jobs.close()
        raise
    server.jobs = jobs
    print(f'GadgetHunter workbench: http://127.0.0.1:{server.server_port}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        jobs.close()


if __name__ == '__main__':
    main()

"""Workbench input, queue, recovery, and local-only HTTP contract tests."""
import base64
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from workbench import Jobs, Handler, extract_sources


def archive(files):
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as out:
        for name, text in files.items():
            out.writestr(name, text)
    return base64.b64encode(data.getvalue()).decode()


class WorkbenchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_archive_extracts_only_java(self):
        count = extract_sources(archive({'src/A.java':'class A {}', 'run.py':'raise Exception()'}), self.root)
        self.assertEqual(count, 1)
        self.assertTrue((self.root/'src/A.java').exists())
        self.assertFalse((self.root/'run.py').exists())

    def test_archive_rejects_traversal_empty_and_invalid(self):
        for data in [archive({'../outside.java':'class A {}'}), archive({'/absolute.java':'x'}), archive({'nothing.txt':'x'}), 'invalid']:
            with self.subTest(data=data[:15]), self.assertRaises(ValueError):
                extract_sources(data, self.root)

    def test_archive_rejects_symlinks(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as out:
            entry = zipfile.ZipInfo('A.java')
            entry.create_system = 3
            entry.external_attr = (0o120777 << 16)
            out.writestr(entry, '/etc/passwd')
        with self.assertRaises(ValueError):
            extract_sources(base64.b64encode(data.getvalue()).decode(), self.root)

    def test_origin_and_host_are_checked(self):
        handler = Handler.__new__(Handler)
        handler.server = Mock(server_port=8765)
        for headers, expected in [
            ({'Host':'127.0.0.1:8765'}, True),
            ({'Host':'localhost:8765', 'Origin':'http://localhost:8765'}, True),
            ({'Host':'evil.example:8765'}, False),
            ({'Host':'127.0.0.1:8765', 'Origin':'https://evil.example'}, False),
            ({'Host':'127.0.0.1:8765', 'Origin':'null'}, False),
        ]:
            handler.headers = headers
            self.assertEqual(handler._allowed(), expected)

    def test_job_submit_cancel_resume_and_no_credentials_in_record(self):
        jobs = Jobs(self.root)
        self.addCleanup(jobs.close)
        payload = {'name':'Review', 'model':'gpt-4.1', 'max_chains':2,
                   'chains':'[VIRTUAL] <A: void a()> --(line:1, constraint:[0])--> <A: void b()>\n',
                   'sources_zip':archive({'A.java':'class A {}'})}
        with patch.dict(os.environ, {'OPENAI_API_KEY':'test-secret'}), patch.object(jobs.executor, 'submit') as enqueue:
            record = jobs.submit(payload)
            self.assertEqual(enqueue.call_count, 1)
            self.assertEqual(record['status'], 'queued')
            job_id = record['id']
            self.assertNotIn('test-secret', (self.root/job_id/'job.json').read_text())
            self.assertEqual(jobs.action(job_id, 'cancel')['status'], 'cancelled')
            self.assertEqual(jobs.action(job_id, 'resume')['status'], 'queued')
            self.assertEqual(enqueue.call_count, 2)
            with self.assertRaises(ValueError):
                jobs.action(job_id, 'resume')
        with self.assertRaises(ValueError):
            Jobs(self.root)

    def test_restart_marks_unfinished_job_interrupted(self):
        folder = self.root / ('a'*32)
        folder.mkdir()
        (folder/'job.json').write_text(json.dumps({'id':'a'*32,'status':'running'}))
        jobs=Jobs(self.root)
        self.addCleanup(jobs.close)
        self.assertEqual(jobs.records['a'*32]['status'],'interrupted')

    def test_invalid_input_leaves_no_job(self):
        jobs=Jobs(self.root)
        self.addCleanup(jobs.close)
        with patch.dict(os.environ, {'OPENAI_API_KEY':'test-key'}), self.assertRaises(ValueError):
            jobs.submit({'chains':'invalid chains', 'sources_zip':archive({'A.java':'class A {}'})})
        self.assertEqual(jobs.records,{})
        self.assertEqual(list(self.root.glob('*/job.json')),[])

if __name__ == '__main__':
    unittest.main()

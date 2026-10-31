import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

from scan_rules.runner import collector_progress, run_backend
import test_candidate_runner as runner_fixtures
from scan_rules.runner import ROOT


def journal(*, exhausted=False):
    return dict(schema_version=1, strategy='round-robin-v1',
                status='partial' if exhausted else 'completed', candidate_count=1,
                budget_exhausted=exhausted, exhaustive=False,
                sinks=[dict(method='sink', incoming_edges=2, controllable_edges=2,
                            scheduled_edges=2, finished_edges=1 if exhausted else 2,
                            budget_exhausted_edges=int(exhausted), pending_edges=0, candidates=1)])


class CollectorJournalTests(unittest.TestCase):
    def test_accounting_rejects_lost_work_and_inconsistent_completion(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'collector.json'
            for exhausted in (False, True):
                value = journal(exhausted=exhausted)
                path.write_text(json.dumps(value))
                self.assertEqual(collector_progress(path, {'sink'}), (value, []))
            bad_values = []
            for key, value in (('pending_edges', 1), ('scheduled_edges', 0), ('candidates', 2), ('method', 'unknown')):
                bad = copy.deepcopy(journal())
                bad['sinks'][0][key] = value
                bad_values.append(bad)
            bad = journal(exhausted=True)
            bad['status'] = 'completed'
            bad_values.extend([bad, [], {'schema_version': 1}])
            for value in bad_values:
                path.write_text(json.dumps(value))
                report, errors = collector_progress(path, {'sink'})
                self.assertIsNone(report)
                self.assertTrue(errors)

    def test_budget_exhaustion_and_unverified_journal_cannot_report_completion(self):
        for value, expected in ((journal(), 'completed'), (journal(exhausted=True), 'partial'), (None, 'partial'), ({}, 'partial')):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temporary:
                # Reuse the process fixture, but execute the real runner and output validation.
                fixture = runner_fixtures.CandidateRunnerTests()
                fixture.folder = Path(temporary)
                folder, java = fixture.fake_prepared()
                knowledge = yaml.safe_load((folder / 'knowledge.yml').read_text())
                knowledge['sinks'] = [{'method': 'sink'}]
                (folder / 'knowledge.yml').write_text(yaml.safe_dump(knowledge))
                if value is not None:
                    script = Path(java)
                    script.write_text(script.read_text().replace('time.sleep(',
                        f"(out/'collector.json').write_text({json.dumps(value)!r})\ntime.sleep("))
                with patch('scan_rules.backend.backend_arguments', return_value=([], {'mode': 'test'})):
                    result = run_backend(folder, java=java, collector='fair', timeout=3, heap_mb=256)
                self.assertEqual(result['status'], expected, result)
                self.assertEqual(result['candidate_count'], 1)
                self.assertFalse(result['coverage']['exhaustive'])

    @unittest.skipUnless(shutil.which('javac') and shutil.which('java'), 'JDK required')
    def test_suspended_traversal_matches_independent_path_enumeration(self):
        with tempfile.TemporaryDirectory() as temporary:
            subprocess.run(['javac', '--release', '17', '-d', temporary,
                            str(ROOT / 'backend/fair/src/gadgethunter/backend/BackwardSearch.java'),
                            str(ROOT / 'backend/fair/src/gadgethunter/backend/DeepeningSearch.java'),
                            str(ROOT / 'tests/fixtures/taint/BackwardSearchProbe.java')], check=True, capture_output=True)
            result = subprocess.run(['java', '-cp', temporary, 'BackwardSearchProbe'],
                                    check=True, capture_output=True, text=True, timeout=20)
            self.assertIn('BACKWARD_SEARCH_OK cases=3600', result.stdout)

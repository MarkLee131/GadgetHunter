import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import yaml

from prepare_scan import prepare
from scan_rules.backend import backend_arguments, build_overlay, JAR, SOURCE
from scan_rules.runner import log_progress, read_candidates, run_backend

ROOT = Path(__file__).resolve().parents[1]


class BackendSelectionTests(unittest.TestCase):
    def test_auto_fallback_is_recorded_and_explicit_optimization_fails_closed(self):
        with patch('scan_rules.backend.build_overlay', side_effect=ValueError('unsupported backend')):
            args, evidence = backend_arguments('/unused', mode='auto')
            self.assertEqual(args, ['-jar', str(JAR)])
            self.assertEqual(evidence['fallback_reason'], 'unsupported backend')
            with self.assertRaisesRegex(ValueError, 'unsupported backend'):
                backend_arguments('/unused', mode='optimized')
        with self.assertRaisesRegex(ValueError, 'Backend must be'):
            backend_arguments('/unused', mode='unexpected')
        with self.assertRaisesRegex(ValueError, 'requires'):
            backend_arguments('/unused', mode='stock', collector='fair')
        with patch('scan_rules.backend.build_overlay', side_effect=ValueError('unsupported backend')):
            with self.assertRaisesRegex(ValueError, 'unsupported backend'):
                backend_arguments('/unused', mode='auto', collector='fair')

    def test_progress_distinguishes_graph_analysis_from_candidate_collection(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'backend.log'
            path.write_text('deserialization call graph starts ...\n'
                            'deserialization call graph finishes, elapsed time: 42.54s\n'
                            'collect gc starts ...\nbackward from <Target: void sink()>\n')
            report = log_progress(path)
            self.assertEqual(report['phase'], 'candidate-collection')
            self.assertEqual(report['call_graph_seconds'], 42.54)
            self.assertEqual(report['current_sink'], '<Target: void sink()>')


@unittest.skipUnless(shutil.which('javac') and shutil.which('java'), 'JDK required')
class BackendOptimizationTests(unittest.TestCase):
    def test_all_helper_methods_match_bundled_backend_and_parallel_calls(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            artifact, evidence = build_overlay(directory)
            with zipfile.ZipFile(artifact) as archive:
                self.assertEqual(archive.namelist(), ['pascal/taie/util/Strings.class'])
            self.assertEqual(evidence['source_sha256'], hashlib.sha256(SOURCE.read_bytes()).hexdigest())
            self.assertEqual(evidence['overlay_sha256'], hashlib.sha256(artifact.read_bytes()).hexdigest())
            probe = directory / 'probe'
            probe.mkdir()
            subprocess.run(['javac', '--release', '17', '-d', str(probe),
                            str(ROOT / 'tests/fixtures/taint/StringsParityProbe.java')], check=True, capture_output=True)
            result = subprocess.run(['java', '-cp', str(probe), 'StringsParityProbe', str(JAR), str(artifact)],
                                    check=True, capture_output=True, text=True, timeout=20)
            self.assertIn('STRING_HELPER_PARITY_OK cases=30100 concurrent=8000', result.stdout)
            self.assertFalse(any(directory.glob('.backend-build-*')))

    def test_unvalidated_backend_is_rejected_before_compilation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'compatibility.json'
            path.write_text(json.dumps({'backend_sha256': 'not-this-backend'}))
            with patch('scan_rules.backend.COMPATIBILITY', path), patch('scan_rules.backend.subprocess.run') as compiler:
                with self.assertRaisesRegex(ValueError, 'has not been validated'):
                    build_overlay(temporary)
                compiler.assert_not_called()

    @unittest.skipUnless(os.environ.get('GADGETHUNTER_TEST_JAVA8_HOME'), 'Java 8 target runtime required')
    def test_scoped_search_candidates_are_equal_with_and_without_optimization(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            classes = directory / 'classes'
            classes.mkdir()
            subprocess.run(['javac', '--release', '8', '-d', str(classes),
                            str(ROOT / 'tests/fixtures/taint/EffectProbe.java')], check=True, capture_output=True)
            candidates = {}
            for name, mode, collector in (('stock', 'stock', 'stock'), ('optimized', 'optimized', 'stock'),
                                          ('fair', 'optimized', 'fair'), ('sanitized-stock', 'stock', 'stock'),
                                          ('sanitized-fair', 'optimized', 'fair')):
                folder = directory / name
                prepare([classes], [], os.environ['GADGETHUNTER_TEST_JAVA8_HOME'], folder, ['native-core'])
                config = yaml.safe_load((folder / 'config.yml').read_text())
                config['sources'] = [source for source in config['sources'] if source.startswith('<fixtures.')]
                (folder / 'config.yml').write_text(yaml.safe_dump(config))
                if name.startswith('sanitized-'):
                    # Deliberately suppress one known positive to verify the backend's
                    # sanitizer predicate is still called. This is not a built-in rule.
                    knowledge = yaml.safe_load((folder / 'knowledge.yml').read_text())
                    knowledge['sanitizers'] = [{'method': '<fixtures.EffectProbe: java.lang.Object readResolve()>'}]
                    (folder / 'knowledge.yml').write_text(yaml.safe_dump(knowledge))
                report = run_backend(folder, timeout=45, heap_mb=1024, backend=mode, collector=collector)
                self.assertEqual(report['status'], 'completed', report)
                self.assertEqual(report['backend_optimization']['mode'], mode)
                candidates[name] = {tuple(chain) for chain in read_candidates(folder / 'chains')['chains']}
                if collector == 'fair':
                    self.assertEqual(report['collector_errors'], [])
                    self.assertEqual(report['collector']['status'], 'completed')
                    self.assertEqual(len(report['collector']['sinks']), 12)
                    self.assertEqual(report['coverage']['internal_budget_exhaustion'], 'collector_reported')
                    if name.startswith('sanitized-'):
                        self.assertGreater(sum(s['sanitizer_prunes'] for s in report['collector']['sinks']), 0)
            self.assertEqual(candidates['stock'], candidates['optimized'])
            self.assertEqual(candidates['stock'], candidates['fair'])
            self.assertEqual(len(candidates['stock']), 2)
            self.assertEqual(candidates['sanitized-stock'], candidates['sanitized-fair'])
            self.assertEqual(len(candidates['sanitized-fair']), 1)
            self.assertIn('<fixtures.NestedProbe:', str(candidates['sanitized-fair']))

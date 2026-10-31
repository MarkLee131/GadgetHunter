import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

from evaluate_dependencies import CATALOG, ROOT, PROBE, MARKER_PROBE, acquire_artifact, candidate_observations, policy_checks, marker_checks
from prepare_scan import prepare
from scan_rules.runner import run_backend


class DependencyEvidenceTests(unittest.TestCase):
    def test_unreviewed_bytes_never_reach_policy_probe(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'unreviewed.jar'
            path.write_bytes(b'not a reviewed release')
            case = json.loads(CATALOG.read_text())['cases'][0]
            with patch('evaluate_dependencies.subprocess.run') as process:
                with self.assertRaisesRegex(ValueError, 'differs from'):
                    policy_checks(case, path, '/unused', '/unused')
                process.assert_not_called()

    def test_artifact_snapshot_requires_exact_size_and_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'cache').mkdir()
            source = root / 'cache/library.jar'
            source.write_bytes(b'reviewed fixture')
            case = dict(id='fixture', maven_path='library.jar', bytes=source.stat().st_size,
                        sha256=hashlib.sha256(source.read_bytes()).hexdigest())
            evidence = acquire_artifact(case, source.parent, root / 'captured.jar')
            self.assertEqual(evidence['sha256'], case['sha256'])
            source.write_bytes(b'other contents!!')
            with self.assertRaisesRegex(ValueError, 'differs from'):
                acquire_artifact(case, source.parent, root / 'bad.jar')
            self.assertFalse((root / 'bad.jar').exists())

    def test_library_attribution_uses_owners_not_parameter_type_mentions(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'chains'
            first = '[VIRTUAL] <App: void call(org.apache.commons.collections.functors.InvokerTransformer)> --(line:1, constraint:[0])--> <java.lang.Runtime: java.lang.Process exec(java.lang.String)>'
            second = '[VIRTUAL] <org.apache.commons.collections.functors.InvokerTransformer: java.lang.Object transform(java.lang.Object)> --(line:2, constraint:[0])--> <java.lang.reflect.Method: java.lang.Object invoke(java.lang.Object,java.lang.Object[])>'
            path.write_text(first + '\n\n' + second + '\n\n')
            observed = candidate_observations(path, {'package': 'org.apache.commons.collections'})
            self.assertEqual(observed['candidate_count'], 2)
            self.assertEqual(observed['library_candidate_ids'], [1])
            self.assertEqual(observed['invoker_transformer_candidate_ids'], [1])
            self.assertEqual(observed['exploitability'], 'not-evaluated')

    def test_marker_shape_requires_callback_and_ordered_library_owners(self):
        package = 'org.apache.commons.collections'
        methods = ['<java.util.HashMap: void readObject(java.io.ObjectInputStream)>',
                   f'<{package}.keyvalue.TiedMapEntry: int hashCode()>',
                   f'<{package}.map.LazyMap: java.lang.Object get(java.lang.Object)>',
                   f'<{package}.functors.InvokerTransformer: java.lang.Object transform(java.lang.Object)>',
                   '<java.lang.reflect.Method: java.lang.Object invoke(java.lang.Object,java.lang.Object[])>']
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'chains'
            orders = [methods, [methods[0], methods[2], methods[1], methods[3], methods[4]]]
            path.write_text(''.join(''.join(f'[VIRTUAL] {a} --(line:1, constraint:[0])--> {b}\n'
                                           for a, b in zip(order, order[1:])) + '\n' for order in orders))
            observed = candidate_observations(path, {'package': package})
            self.assertEqual(observed['invoker_transformer_candidate_ids'], [0, 1])
            self.assertEqual(observed['marker_graph_shape_candidate_ids'], [0])


@unittest.skipUnless(os.environ.get('GADGETHUNTER_TEST_JAVA8_HOME') and shutil.which('javac'), 'Java 8 target and host JDK required')
class ReflectionBoundaryTests(unittest.TestCase):
    def test_controlled_selection_and_constant_target_negatives(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            classes = root / 'classes'
            classes.mkdir()
            subprocess.run(['javac', '--release', '8', '-d', str(classes),
                            str(ROOT / 'tests/fixtures/taint/ReflectionProbe.java')], check=True, capture_output=True)
            home = os.environ['GADGETHUNTER_TEST_JAVA8_HOME']
            prepared = root / 'prepared'
            prepare([classes], [], home, prepared, ['native-core', 'reflection-boundaries'])
            config_path = prepared / 'config.yml'
            config = yaml.safe_load(config_path.read_text())
            config['sources'] = [source for source in config['sources'] if source.startswith('<fixtures.')]
            config_path.write_text(yaml.safe_dump(config))
            report = run_backend(prepared, backend='optimized', collector='fair', timeout=45, heap_mb=1024)
            self.assertEqual(report['status'], 'completed', report)
            self.assertEqual(report['progress']['loaded_rules']['sinks'], 14)
            self.assertEqual(report['collector']['edge_order'], 'callback-distance-v1')
            self.assertEqual(report['collector']['depth_strategy'], 'round-robin-deepening-v1')
            self.assertGreater(report['collector']['distance_index_methods'], 0)
            chains = (prepared / 'chains').read_text()
            self.assertIn('<fixtures.ReflectionProbe:', chains)
            self.assertIn('<fixtures.ConstructorProbe:', chains)
            self.assertNotIn('<fixtures.ConstantReflectionProbe:', chains)
            self.assertNotIn('<fixtures.ConstantConstructorProbe:', chains)
            self.assertEqual(report['candidate_count'], 2)
            with self.assertRaisesRegex(ValueError, 'suppress boundaries'):
                prepare([classes], [], home, root / 'incompatible', ['native-core', 'reflection-boundaries', 'reflection-dispatch'])


@unittest.skipUnless(os.environ.get('GADGETHUNTER_TEST_JAVA8_HOME') and os.environ.get('GADGETHUNTER_TEST_MAVEN_REPOSITORY') and shutil.which('javac'),
                     'Java 8 and reviewed Maven artifacts required')
class RealDependencyPolicyTests(unittest.TestCase):
    def test_reviewed_releases_with_isolated_marker_and_callback_graph(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            subprocess.run(['javac', '--release', '8', '-d', str(folder), str(PROBE), str(MARKER_PROBE)],
                           check=True, capture_output=True)
            for case in json.loads(CATALOG.read_text())['cases']:
                jar = Path(os.environ['GADGETHUNTER_TEST_MAVEN_REPOSITORY']) / case['maven_path']
                for check in (policy_checks, marker_checks):
                    with self.subTest(case=case['id'], oracle=check.__name__):
                        results = check(case, jar, os.environ['GADGETHUNTER_TEST_JAVA8_HOME'], folder)
                        self.assertTrue(all(result['matches'] for result in results), results)

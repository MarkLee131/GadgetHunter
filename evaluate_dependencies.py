#!/usr/bin/env python3
"""Reproduce pinned real-library scans and harmless serialization-policy checks."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import urllib.request

from prepare_scan import PROFILES, prepare
from scan_rules.runner import atomic_report, read_candidates, run_backend

ROOT = Path(__file__).resolve().parent
CATALOG = ROOT / 'evaluation/dependencies.json'
PROBE = ROOT / 'evaluation/SerializationPolicyProbe.java'
MARKER_PROBE = ROOT / 'evaluation/MarkerGraphProbe.java'
OWNERS = re.compile(r'^\[[A-Z]+\] <([^:]+): .+> --\(line:-?\d+,\s*constraint:\[[^\]]*\]\)--> <([^:]+): .+>$')


def verified_artifact(path, case):
    data = Path(path).read_bytes()
    if len(data) != case['bytes'] or hashlib.sha256(data).hexdigest() != case['sha256']:
        raise ValueError(f"Artifact differs from the reviewed release: {case['id']}")
    return data


def acquire_artifact(case, repository, destination, fetch=False):
    local = Path(repository) / case['maven_path']
    if local.is_file():
        data = verified_artifact(local, case)
        source = 'local-maven-cache'
    elif fetch:
        url = 'https://repo.maven.apache.org/maven2/' + case['maven_path']
        with urllib.request.urlopen(url, timeout=30) as response:
            data = response.read(case['bytes'] + 1)
        if len(data) != case['bytes'] or hashlib.sha256(data).hexdigest() != case['sha256']:
            raise ValueError(f"Downloaded artifact differs from reviewed release: {case['id']}")
        source = url
    else:
        raise ValueError(f"Missing {local}; supply --maven-repository or --fetch")
    destination.write_bytes(data)
    return dict(sha256=case['sha256'], bytes=len(data), source=source)


def policy_checks(case, jar, java8_home, probe_classes):
    verified_artifact(jar, case)
    # No inherited Java flags, agent injection, provider keys or unsafe property.
    environment = {'PATH': os.defpath}
    java = str(Path(java8_home) / 'bin/java')
    checks = []
    for policy in ('default', 'enabled'):
        result = subprocess.run([java, '-Xmx128m', '-cp', os.pathsep.join((str(probe_classes), str(jar))),
                                 'SerializationPolicyProbe', case['package'] + '.functors.InvokerTransformer', policy],
                                env=environment, capture_output=True, text=True, timeout=15, check=True)
        observed = json.loads(result.stdout)
        expected = case[policy + '_policy']
        if observed.get('class') != case['package'] + '.functors.InvokerTransformer' or observed.get('policy') != policy:
            raise ValueError('Unexpected policy probe identity')
        checks.append(dict(observed, expected=expected, matches=observed.get('outcome') == expected))
    return checks


def candidate_observations(path, case):
    parsed = read_candidates(path)
    library_ids, invoker_ids, marker_shape_ids, effects = [], [], [], {}
    for index, chain in enumerate(parsed['chains']):
        owners = {owner for edge in chain for owner in OWNERS.fullmatch(edge).groups()}
        if any(owner.startswith(case['package'] + '.') for owner in owners):
            library_ids.append(index)
            terminal = chain[-1].rsplit('--> ', 1)[-1]
            effects[terminal] = effects.get(terminal, 0) + 1
        if case['package'] + '.functors.InvokerTransformer' in owners:
            invoker_ids.append(index)
            flow = [OWNERS.fullmatch(edge).group(1) for edge in chain] + [OWNERS.fullmatch(chain[-1]).group(2)]
            expected = iter(('java.util.HashMap', case['package'] + '.keyvalue.TiedMapEntry',
                             case['package'] + '.map.LazyMap', case['package'] + '.functors.InvokerTransformer',
                             'java.lang.reflect.Method'))
            wanted = next(expected)
            for owner in flow:
                if owner == wanted:
                    wanted = next(expected, None)
            if (wanted is None and ': void readObject(java.io.ObjectInputStream)>' in chain[0].split(' --(', 1)[0]
                    and flow[0] == 'java.util.HashMap'
                    and chain[-1].endswith('<java.lang.reflect.Method: java.lang.Object invoke(java.lang.Object,java.lang.Object[])>')):
                marker_shape_ids.append(index)
    return dict(candidate_count=len(parsed['chains']), library_candidate_count=len(library_ids),
                library_candidate_ids=library_ids, invoker_transformer_candidate_count=len(invoker_ids),
                invoker_transformer_candidate_ids=invoker_ids, library_terminal_methods=effects,
                marker_graph_shape_candidate_ids=marker_shape_ids,
                chains_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                output_errors=parsed['errors'], exploitability='not-evaluated')


def marker_checks(case, jar, java8_home, probe_classes):
    verified_artifact(jar, case)
    checks = []
    for policy in ('default', 'enabled'):
        result = subprocess.run([str(Path(java8_home) / 'bin/java'), '-Xmx128m', '-cp',
                                 os.pathsep.join((str(probe_classes), str(jar))), 'MarkerGraphProbe', case['package'], policy],
                                env={'PATH': os.defpath}, capture_output=True, text=True, timeout=15, check=True)
        observed = json.loads(result.stdout)
        expected = case[policy + '_policy']
        if observed.get('oracle') != 'hashmap-lazymap-marker-v1' or observed.get('policy') != policy:
            raise ValueError('Unexpected marker oracle identity')
        matches = observed.get('outcome') == expected and observed.get('marker_visits') == (1 if expected == 'permitted' else 0)
        checks.append(dict(observed, expected=expected, matches=matches))
    return checks


def evaluate(args):
    catalog = json.loads(CATALOG.read_text())
    cases = [case for case in catalog['cases'] if not args.case or case['id'] in args.case]
    java = shutil.which(args.java)
    if not java:
        raise ValueError('Host Java executable was not found.')
    compiler = Path(java).resolve().parent / 'javac'
    target = Path(args.java8_home).expanduser().resolve(strict=True)
    if not (target / 'bin/java').is_file():
        raise ValueError('Target Java home must contain bin/java.')
    if not any((target / path).is_file() for path in ('jre/lib/rt.jar', 'lib/rt.jar')):
        raise ValueError('Target Java home must supply a Java 8 rt.jar.')
    output = Path(args.output).expanduser().absolute()
    output.mkdir(parents=True, exist_ok=False)
    artifacts, probe = output / 'artifacts', output / 'probe'
    artifacts.mkdir()
    probe.mkdir()
    subprocess.run([str(compiler), '-proc:none', '--release', '8', '-d', str(probe), str(PROBE), str(MARKER_PROBE)],
                   capture_output=True, text=True, timeout=30, check=True)
    report = dict(schema_version=1, status='running', started_at=time.time(),
                  label_scope=catalog['label_scope'], primary_source=catalog['source'],
                  catalog_sha256=hashlib.sha256(CATALOG.read_bytes()).hexdigest(),
                  evaluator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  probe_sha256=hashlib.sha256(PROBE.read_bytes()).hexdigest(),
                  marker_probe_sha256=hashlib.sha256(MARKER_PROBE.read_bytes()).hexdigest(),
                  host_java=subprocess.run([java, '-version'], capture_output=True, text=True, check=True, timeout=10).stderr.strip(),
                  target_java=subprocess.run([str(target / 'bin/java'), '-version'], env={'PATH': os.defpath},
                                             capture_output=True, text=True, check=True, timeout=10).stderr.strip(),
                  profiles=args.profile or ['native-core'], collector=args.collector,
                  policy_only=args.policy_only, llm_calls=0, cases=[],
                  limitations=['The fixed marker graph validates one harmless callback; it does not validate arbitrary candidate graphs or dangerous effects.',
                               'The marker oracle adds a local marker class absent from library-only scans; it is not a same-classpath recall label.',
                               'Presence and absence of candidates are not vulnerability verdicts.',
                               'Partial scans are included; no precision/recall estimate is computed.'])
    path = output / 'evaluation.json'
    atomic_report(path, report)
    interrupted = False
    try:
        for case in cases:
            record = {'id': case['id'], 'status': 'running'}
            report['cases'].append(record)
            atomic_report(path, report)
            try:
                jar = artifacts / Path(case['maven_path']).name
                record['artifact'] = acquire_artifact(case, args.maven_repository, jar, args.fetch)
                record['policy_checks'] = policy_checks(case, jar, target, probe)
                record['marker_checks'] = marker_checks(case, jar, target, probe)
                if not all(check['matches'] for check in record['policy_checks'] + record['marker_checks']):
                    raise ValueError('Policy probe disagrees with reviewed labels; investigate before using this case.')
                record['status'] = 'policy-checked'
                if not args.policy_only:
                    prepared = output / case['id']
                    started = time.monotonic()
                    prepare([jar], [], target, prepared, report['profiles'])
                    record['preparation_seconds'] = round(time.monotonic() - started, 2)
                    execution = run_backend(prepared, timeout=args.timeout, heap_mb=args.heap_mb,
                                            java=java, backend=args.backend, collector=args.collector)
                    record['scan'] = {key: execution.get(key) for key in
                                      ('status', 'elapsed_seconds', 'selected_root_count', 'candidate_count', 'limits',
                                       'progress', 'coverage', 'inventory_sha256', 'knowledge_sha256', 'config_sha256',
                                       'backend_sha256', 'backend_optimization', 'collector', 'collector_errors')}
                    record['observations'] = candidate_observations(prepared / 'chains', case)
                    record['status'] = execution['status']
                    if record['status'] == 'cancelled':
                        interrupted = True
                        break
            except (ValueError, OSError, subprocess.SubprocessError) as exc:
                record.update(status='failed', error=f'{type(exc).__name__}: {exc}')
            finally:
                atomic_report(path, report)
            print(f"{case['id']}: {record['status']}", flush=True)
    except KeyboardInterrupt:
        interrupted = True
        if report['cases'] and report['cases'][-1]['status'] in ('running', 'policy-checked'):
            report['cases'][-1]['status'] = 'cancelled'
    finally:
        statuses = {case['status'] for case in report['cases']}
        report.update(status='cancelled' if interrupted else 'failed' if 'failed' in statuses
                      else 'partial' if 'partial' in statuses else 'completed', finished_at=time.time())
        atomic_report(path, report)
    return report


def main():
    catalog = json.loads(CATALOG.read_text())
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', action='append', choices=[case['id'] for case in catalog['cases']])
    parser.add_argument('--maven-repository', default=str(Path.home() / '.m2/repository'))
    parser.add_argument('--fetch', action='store_true', help='Fetch missing pinned artifacts from Maven Central')
    parser.add_argument('--output', required=True, help='New evidence directory')
    parser.add_argument('--java8-home', required=True)
    parser.add_argument('--java', default='java')
    parser.add_argument('--profile', action='append', choices=PROFILES)
    parser.add_argument('--backend', choices=('auto', 'stock', 'optimized'), default='optimized')
    parser.add_argument('--collector', choices=('stock', 'fair'), default='fair')
    parser.add_argument('--timeout', type=int, default=120)
    parser.add_argument('--heap-mb', type=int, default=4096)
    parser.add_argument('--policy-only', action='store_true', help='Check harmless marker policies without scanning')
    args = parser.parse_args()
    if args.timeout <= 0 or args.heap_mb < 256 or (args.collector == 'fair' and args.backend == 'stock'):
        parser.error('Use positive timeout, heap >= 256 MiB, and auto/optimized backend for fair collection.')
    try:
        report = evaluate(args)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))
    print(f"{report['status']}: {Path(args.output).absolute() / 'evaluation.json'}")
    return {'completed': 0, 'partial': 2, 'failed': 1, 'cancelled': 130}[report['status']]


if __name__ == '__main__':
    raise SystemExit(main())

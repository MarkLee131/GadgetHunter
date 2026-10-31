"""Build a source-available, fingerprinted optimization over a supported backend."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'backend/strings/src/pascal/taie/util/Strings.java'
COMPATIBILITY = ROOT / 'backend/strings/compatibility.json'
JAR = ROOT / 'multi-agents/flash/flash.jar'


def build_overlay(directory, *, java='java', collector='stock'):
    """Compile only our checked-in helper, never classes supplied by a target."""
    compatible = json.loads(COMPATIBILITY.read_text())
    if collector not in ('stock', 'fair'):
        raise ValueError('Collector must be stock or fair.')
    if hashlib.sha256(JAR.read_bytes()).hexdigest() != compatible['backend_sha256']:
        raise ValueError('This backend build has not been validated with the string optimization.')
    with zipfile.ZipFile(JAR) as archive:
        original = archive.read('pascal/taie/util/Strings.class')
        plan = archive.read('tai-e-analyses.yml')
    if hashlib.sha256(original).hexdigest() != compatible['original_class_sha256']:
        raise ValueError('Backend helper differs from the validated implementation.')
    executable = shutil.which(str(java))
    if not executable:
        raise ValueError('Java executable was not found.')
    # A host JDK selected explicitly should use its matching compiler.
    compiler = Path(executable).resolve().parent / 'javac'
    if not compiler.is_file() or not os.access(compiler, os.X_OK):
        raise ValueError('A matching JDK compiler is unavailable; use JDK 17+ for optimized scans.')
    version = subprocess.run([str(compiler), '-version'], capture_output=True, text=True, timeout=10, check=True)
    source = SOURCE.read_bytes()
    sources = {str(SOURCE.relative_to(ROOT)): source}
    if collector == 'fair':
        for name in ('BackwardSearch', 'DeepeningSearch', 'FairCollector', 'FairSummaryDriver'):
            path = ROOT / f'backend/fair/src/gadgethunter/backend/{name}.java'
            sources[str(path.relative_to(ROOT))] = path.read_bytes()
        old = b'analysisClass: pascal.taie.analysis.dataflow.analysis.SummaryAnalysisDriver'
        if plan.count(old) != 1:
            raise ValueError('Unexpected backend analysis registry; cannot select fair collector.')
        plan = plan.replace(old, b'analysisClass: gadgethunter.backend.FairSummaryDriver')
    directory = Path(directory)
    with tempfile.TemporaryDirectory(prefix='.backend-build-', dir=directory) as temporary:
        temporary = Path(temporary)
        (temporary / 'source').mkdir()
        captured_sources = []
        for name, content in sources.items():
            captured = temporary / 'source' / Path(name).name
            captured.write_bytes(content)
            captured_sources.append(str(captured))
        classes = temporary / 'classes'
        classes.mkdir()
        result = subprocess.run([str(compiler), '-proc:none', '--release', '17', '-cp', str(JAR),
                                 '-d', str(classes), *captured_sources], capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise ValueError('Backend optimization compilation failed: ' + result.stderr[-2000:])
        artifact = temporary / 'backend-overlay.jar'
        with zipfile.ZipFile(artifact, 'w') as archive:
            entries = {str(path.relative_to(classes)): path.read_bytes() for path in sorted(classes.rglob('*.class'))}
            if collector == 'fair':
                entries['tai-e-analyses.yml'] = plan
            for name, content in entries.items():
                entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                entry.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(entry, content)
        destination = directory / 'backend-overlay.jar'
        artifact.replace(destination)
    return destination, {'mode': 'optimized', 'optimization': 'fixed-ascii-string-parsing-v1',
                         'source_sha256': hashlib.sha256(source).hexdigest(),
                         'sources': {name: hashlib.sha256(content).hexdigest() for name, content in sources.items()},
                         'collector': collector,
                         'overlay_sha256': hashlib.sha256(destination.read_bytes()).hexdigest(),
                         'compiler': (version.stdout + version.stderr).strip(),
                         'base_backend_sha256': compatible['backend_sha256']}


def backend_arguments(directory, *, mode='auto', java='java', collector='stock'):
    if mode not in ('auto', 'stock', 'optimized'):
        raise ValueError('Backend must be auto, stock, or optimized.')
    if collector not in ('stock', 'fair'):
        raise ValueError('Collector must be stock or fair.')
    if mode == 'stock' and collector != 'stock':
        raise ValueError('Fair collection requires the compatible optimized backend.')
    if mode == 'stock':
        return ['-jar', str(JAR)], {'mode': 'stock', 'requested': mode}
    try:
        artifact, evidence = build_overlay(directory, java=java, collector=collector)
    except (ValueError, OSError, subprocess.SubprocessError, zipfile.BadZipFile) as exc:
        if mode == 'optimized' or collector == 'fair':
            raise ValueError(str(exc)) from exc
        return ['-jar', str(JAR)], {'mode': 'stock', 'requested': mode, 'fallback_reason': str(exc)}
    return ['-cp', os.pathsep.join((str(artifact), str(JAR))), 'pascal.taie.Main'], dict(evidence, requested=mode)

#!/usr/bin/env python3
"""Add file-upload support to the upstream recorder without changing its source."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / '.gadgethunter/tools/demo-video'


def main():
    source = (TOOL / 'record.js').read_text()
    if "case 'upload':" not in source:
        anchor = "      case 'fill':"
        if source.count(anchor) != 1:
            raise RuntimeError('Upstream recorder changed; review the upload adapter before proceeding.')
        source = source.replace(anchor, "      case 'upload': { await page.locator(a.selector).setInputFiles(a.files); await sleep(400); break; }\n" + anchor, 1)
    if 'for (const a of s.before || [])' not in source:
        anchor = '      const s = scenario.steps[i];'
        if source.count(anchor) != 1:
            raise RuntimeError('Upstream recorder changed; review scene preparation before proceeding.')
        source = source.replace(anchor, anchor + '\n      for (const a of s.before || []) await run(a);', 1)
    recorder = TOOL / 'gadgethunter-record.js'
    recorder.write_text(source)
    subprocess.run(['node', str(recorder), 'demos/workbench/scenario.json',
                    '.gadgethunter/demo/recording', *sys.argv[1:]], cwd=ROOT, check=True)


if __name__ == '__main__':
    main()

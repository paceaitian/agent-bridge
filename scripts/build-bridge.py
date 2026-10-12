#!/usr/bin/env python3
"""Offline pure-Python wheel, only from the portable mirror source allowlist.

No setuptools/pip/network during construction. The wheel is verified by pip in
an isolated venv; this is NOT the Windows W4 installation/upgrade qualification.
"""
from __future__ import annotations
import argparse
import base64
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def build(root: Path, out: Path, commit: str) -> Path:
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('full_source_commit_required')
    spec = importlib.util.spec_from_file_location('mirror_bridge', root/'scripts/mirror-bridge.py')
    assert spec and spec.loader
    mirror = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mirror)
    paths = [p for p in mirror.portable_paths(root) if p.startswith('src/agentstatus_bridge/')]
    if 'src/agentstatus_bridge/cli.py' not in paths:
        raise ValueError('bridge_source_missing')
    version = '0.1.0.dev71+g' + commit[:12]
    dist = f'agent_bridge-{version}.dist-info'
    contents = {p.removeprefix('src/'): (root/p).read_bytes() for p in paths}
    source = {'commit':commit, 'files':{p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in paths}}
    contents.update({
        dist+'/METADATA': (f'Metadata-Version: 2.3\nName: agent-bridge\nVersion: {version}\n'
            'Summary: Local collaboration bridge; Windows local core only\nRequires-Python: >=3.12\n\n'
            'Windows provider delivery is NOT enabled. W1 independent audit pending.\n').encode(),
        dist+'/WHEEL': b'Wheel-Version: 1.0\nGenerator: agentstatus-build-bridge\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
        dist+'/entry_points.txt': b'[console_scripts]\nagent-bridge = agentstatus_bridge.cli:main\n',
        dist+'/source.json': (json.dumps(source,sort_keys=True,indent=2)+'\n').encode(),
    })
    record = io.StringIO(newline='')
    writer = csv.writer(record,lineterminator='\n')
    for name, data in sorted(contents.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()
        writer.writerow((name,'sha256='+digest,len(data)))
    writer.writerow((dist+'/RECORD','',''))
    contents[dist+'/RECORD'] = record.getvalue().encode()
    out.mkdir(parents=True,exist_ok=True)
    target = out/f'agent_bridge-{version}-py3-none-any.whl'
    # Exclusive creation: a released filename is never silently overwritten.
    with zipfile.ZipFile(target,'x',compression=zipfile.ZIP_DEFLATED) as wheel:
        for name,data in sorted(contents.items()):
            info = zipfile.ZipInfo(name,(1980,1,1,0,0,0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            wheel.writestr(info,data,compress_type=zipfile.ZIP_DEFLATED)
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out-dir',type=Path,required=True)
    args = parser.parse_args()
    dirty = subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True)
    if dirty:
        raise SystemExit('clean_source_required')
    commit = subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    target = build(ROOT,args.out_dir,commit)
    print(json.dumps({'wheel':str(target),'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'sourceCommit':commit}))


if __name__ == '__main__':
    main()

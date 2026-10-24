"""Independent wheel/portable-closure and CI selection assertions (no install)."""
import base64
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout

ROOT=Path(__file__).resolve().parents[1]


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),ROOT/'scripts'/f'{name}.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


class ReleaseTests(unittest.TestCase):
    def test_wheel_only_contains_bridge_complete_modules_and_valid_record(self):
        builder=load('build-bridge')
        with tempfile.TemporaryDirectory() as temp:
            target=builder.build(ROOT,Path(temp),'a'*40)
            with zipfile.ZipFile(target) as wheel:
                names=set(wheel.namelist())
                sources={p.relative_to(ROOT/'src').as_posix() for p in (ROOT/'src/agentstatus_bridge').rglob('*.py')}
                self.assertEqual({n for n in names if not '.dist-info/' in n},sources)
                dist='agent_bridge-0.1.0.dev71+gaaaaaaaaaaaa.dist-info'
                self.assertEqual(wheel.read(dist+'/entry_points.txt'),b'[console_scripts]\nagent-bridge = agentstatus_bridge.cli:main\n')
                self.assertIn(b'Requires-Python: >=3.12\n',wheel.read(dist+'/METADATA'))
                self.assertIn(b'Tag: py3-none-any\n',wheel.read(dist+'/WHEEL'))
                self.assertNotIn(b'Requires-Dist:',wheel.read(dist+'/METADATA'))
                records=list(csv.reader(io.StringIO(wheel.read(dist+'/RECORD').decode())))
                self.assertEqual({row[0] for row in records},names)
                for name,digest,size in records:
                    if name.endswith('/RECORD'):
                        self.assertEqual((digest,size),('',''));continue
                    data=wheel.read(name)
                    self.assertEqual(digest,'sha256='+base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode())
                    self.assertEqual(int(size),len(data))
                manifest=json.loads(wheel.read(dist+'/source.json'))
                self.assertEqual(manifest['commit'],'a'*40)
                self.assertEqual(set(manifest['files']),{'src/'+n for n in sources})
                for name,digest in manifest['files'].items():
                    self.assertEqual(digest,hashlib.sha256((ROOT/name).read_bytes()).hexdigest())
            with self.assertRaises(FileExistsError):builder.build(ROOT,Path(temp),'a'*40)
            with tempfile.TemporaryDirectory() as second:
                self.assertEqual(target.read_bytes(),builder.build(ROOT,Path(second),'a'*40).read_bytes())

    def test_export_is_standalone_and_includes_support_and_tooling(self):
        mirror=load('mirror-bridge')
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            manifest=mirror.export(ROOT,root,'a'*40,init=True)
            for path in ('scripts/build-bridge.py','scripts/mirror-bridge.py','scripts/verify-bridge-windows.py',
                         'scripts/windows/w1_gate_native.py','scripts/windows/W1-gate-run.py','scripts/windows/W1-gate.ps1',
                         'tests/bridge_platform_guard.py','tests/bridge_winapi.py','tests/bridge_winapi_sdk.py'):
                self.assertIn(path,manifest['files'])
                self.assertEqual((root/path).read_bytes(),(ROOT/path).read_bytes())
            self.assertFalse((root/'src/agentstatus').exists())

    def test_export_requires_init_or_valid_manifest_and_prunes_only_recorded(self):
        mirror=load('mirror-bridge')
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);source=base/'source';target=base/'target';target.mkdir()
            module=source/'src/agentstatus_bridge/retired.py';module.parent.mkdir(parents=True)
            module.write_text('old=1\n');(source/'tests').mkdir()
            with self.assertRaises(SystemExit):mirror.export(source,target,'a'*40)
            mirror.export(source,target,'a'*40,init=True)
            self.assertTrue((target/'src/agentstatus_bridge/retired.py').exists())
            keep=target/'untracked-owner-file';keep.write_bytes(b'keep')
            module.unlink()
            output=io.StringIO()
            with redirect_stdout(output):manifest=mirror.export(source,target,'b'*40)
            self.assertFalse((target/'src/agentstatus_bridge/retired.py').exists())
            self.assertIn('已删除旧清单文件：src/agentstatus_bridge/retired.py',output.getvalue())
            self.assertNotIn('src/agentstatus_bridge/retired.py',manifest['files'])
            self.assertEqual(keep.read_bytes(),b'keep')
            (target/mirror.MANIFEST_RELPATH).unlink()
            with self.assertRaises(SystemExit):mirror.export(source,target,'c'*40,init=True)
            self.assertEqual(keep.read_bytes(),b'keep')

    def test_export_init_ignores_only_top_level_git_and_preserves_it(self):
        mirror=load('mirror-bridge')
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);source=base/'source';source.mkdir();(source/'tests').mkdir()
            target=base/'target';git=target/'.git';(git/'objects').mkdir(parents=True)
            (git/'HEAD').write_bytes(b'ref: refs/heads/main\n')
            (git/'objects/object').write_bytes(b'preserve')
            before={p.relative_to(git):p.read_bytes() for p in git.rglob('*') if p.is_file()}
            with self.assertRaises(SystemExit):mirror.export(source,target,'a'*40)
            error=None
            try:mirror.export(source,target,'a'*40,init=True)
            except SystemExit as exc:error=exc
            self.assertIsNone(error)
            self.assertEqual({p.relative_to(git):p.read_bytes() for p in git.rglob('*') if p.is_file()},before)
            for entry in ('owner-file','.hidden','subdir'):
                with self.subTest(entry=entry):
                    other=base/entry;other.mkdir();(other/'.git').mkdir()
                    path=other/entry
                    if entry=='subdir':path.mkdir()
                    else:path.write_bytes(b'keep')
                    with self.assertRaises(SystemExit):mirror.export(source,other,'a'*40,init=True)
                    self.assertTrue(path.exists())
                    self.assertFalse((other/mirror.MANIFEST_RELPATH).exists())

    def test_export_rejects_unsafe_or_edited_old_manifest_targets_before_writing(self):
        mirror=load('mirror-bridge')
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);source=base/'source';target=base/'target'
            source.mkdir();(source/'tests').mkdir();target.mkdir()
            outside=base/'outside';outside.write_bytes(b'owner')
            manifest={'source':{'repository':'agentstatus'},'files':{}}
            (target/'docs').mkdir()
            for name in ('../outside','/outside','src/../outside','src/link/file'):
                (target/'src').mkdir(exist_ok=True)
                link=target/'src/link'
                if not link.is_symlink():link.symlink_to(base,target_is_directory=True)
                manifest['files']={name:hashlib.sha256(b'owner').hexdigest()}
                (target/mirror.MANIFEST_RELPATH).write_text(json.dumps(manifest))
                with self.assertRaises(SystemExit):mirror.export(source,target,'a'*40)
                self.assertEqual(outside.read_bytes(),b'owner')
            old=target/'src/modified.py';old.write_bytes(b'changed')
            manifest['files']={'src/modified.py':hashlib.sha256(b'old').hexdigest()}
            (target/mirror.MANIFEST_RELPATH).write_text(json.dumps(manifest))
            with self.assertRaises(SystemExit):mirror.export(source,target,'a'*40)
            self.assertEqual(old.read_bytes(),b'changed')

    def test_ci_selection_covers_fake_and_native_without_linux_suite(self):
        ci=load('verify-bridge-windows')
        self.assertEqual(set(ci.MODULES),{'test_bridge_windows','test_bridge_windows_streams','test_bridge_windows_codex','test_bridge_windows_discovery',
            'test_bridge_registration','test_bridge_labels','test_bridge_hints','test_bridge_windows_native','test_bridge_windows_callers',
            'test_bridge_windows_delivery','test_bridge_windows_boundaries','test_bridge_windows_roots',
            'test_bridge_windows_roots_rework','test_bridge_windows_storage','test_bridge_local_display'})
        for name in ci.MODULES:self.assertTrue((ROOT/'tests'/f'{name}.py').is_file())
        native=(ROOT/'tests/test_bridge_windows_native.py').read_text()
        self.assertIn('if api.token(api.k.GetCurrentProcess()).elevated:',native)
        self.assertIn("self.skipTest('non-elevated Store/DACL gate NOT_RUN",native)
        source=(ROOT/'scripts/verify-bridge-windows.py').read_text()
        self.assertLess(source.index('import bridge_platform_guard'),source.index('loadTestsFromNames'))
        self.assertIn('result.testsRun >= 50 and expected_skips',source)

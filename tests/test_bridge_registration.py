"""V71-10/11: same production S with explicit synthetic Windows P/F/kernel."""
from dataclasses import replace
from contextlib import redirect_stdout,redirect_stderr
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

import bridge_support
from bridge_winapi import Kernel
from bridge_winapi_sdk import assert_file_layout
from agentstatus_bridge.platforms.windows import abi as A
from agentstatus_bridge import registration
from agentstatus_bridge.registration import Registry, Proof, MAX_RECORD, FIELDS, main, key
from agentstatus_bridge.platforms.factory import make_platform, using_platform
from agentstatus_bridge.platforms.types import Presence, ProcessIdentity


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        assert_file_layout(self,A.FILE_INFORMATION)
        # 夹具锁无竞争；产品 1 秒时限在慢 CI runner 上会被建目录与开锁文件用完（2026-11-18 公开镜像 Windows CI
        # 首跑 registration_deadline），写入、清理、退役都改给宽裕时限；专测过期的用例自己传入已过去的 deadline
        budget=patch.object(registration,'BUDGET',30.0);budget.start();self.addCleanup(budget.stop)
        self.tmp=TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.k=Kernel(self.root)
        self.p=make_platform('windows',win_api=self.k.api)
        self.r=Registry(self.root,self.p)
        self.writer=ProcessIdentity('windows',100,'win-filetime','134362090001712230')
        self.proof=Proof(self.writer,'tui','root')
        self.id='019a0000-0000-7000-8000-000000000001'
        self.payload={'hook_event_name':'SessionStart','session_id':self.id,
                      'prompt':'PRIVATE_CANARY','cwd':'PRIVATE_CANARY','token':'PRIVATE_CANARY',
                      'transcript_path':'PRIVATE_CANARY','agentProcess':{'pid':999}}
    def tearDown(self): self.assertEqual(self.k.handles,{})
    def write(self, **kw):
        options={'provider':'claude','writer':self.writer,'now':100.,'proof':self.proof,'fixture':True}
        options.update(kw)
        return self.r.write(self.payload,**options)
    def test_whitelist_same_pid_distinct_session_and_untrusted_hook(self):
        self.assertEqual(self.write(),'recorded')
        self.payload['session_id']='019a0000-0000-7000-8000-000000000002'
        self.assertEqual(self.write(),'recorded')
        paths=list(self.r.root.glob('*.json'))
        self.assertEqual(len(paths),2)
        for p in paths:
            raw=p.read_bytes();record=json.loads(raw)
            self.assertLessEqual(len(raw),MAX_RECORD)
            self.assertEqual(set(record),FIELDS)
            self.assertNotIn(b'PRIVATE_CANARY',raw)
            self.assertNotIn(b'"pid":999',raw)
        result=self.r.load()
        self.assertTrue(result.complete)
        self.assertFalse(any(x['qualified'] for x in result.records))
        self.assertTrue(all(x['qualified'] for x in self.r.load(qualify=lambda _:True).records))
        self.assertEqual(self.write(provider='codex'),'recorded')
        codex=[x for x in self.r.load(qualify=lambda _:True).records if x['provider']=='codex'][0]
        self.assertIsNone(codex['agentProcess'])
        self.assertEqual(codex['sessionKind'],'unknown')
        self.assertFalse(codex['qualified'])
    def test_unproven_ancestor_and_identity_never_write_bound(self):
        other=ProcessIdentity('windows',999,'win-filetime','134362090001712229')
        self.assertEqual(self.write(proof=Proof(other,'tui','root')),'source_unqualified')
        self.assertFalse(self.r.root.exists())
        self.assertEqual(self.r.load().records,())
        self.assertTrue(self.r.load().complete)
        self.k.files[str(self.root)]={'reparse':True}
        self.assertFalse(self.r.load().complete)
        self.assertEqual(self.r.load().reason,'registration_store_unverified')
        with patch.object(self.p.process,'same_generation',return_value=Presence.UNKNOWN):
            self.assertEqual(self.write(),'writer_unverified')
        self.assertFalse(self.r.root.exists())

    def test_reader_rejects_non_claude_even_when_valid_proof_is_present(self):
        self.assertEqual(self.write(),'recorded')
        path=next(self.r.root.glob('*.json'))
        record=json.loads(path.read_text(encoding='utf-8'));record['provider']='codex'
        self.p.files.atomic_write(self.r.root,json.dumps(record).encode(),name=key(record)+'.json',prefix='.r.')
        rows=self.r.load(qualify=lambda _:True).records
        codex=[row for row in rows if row['provider']=='codex']
        self.assertEqual(len(codex),1)
        self.assertIsNotNone(codex[0]['agentProcess'])
        self.assertFalse(codex[0]['qualified'])

    def test_cleanup_single_snapshot_and_revalidates_each_file_attribute(self):
        self.assertEqual(self.write(),'recorded')
        for n in range(2,5):
            self.payload['session_id']=f'019a0000-0000-7000-8000-{n:012x}'
            self.assertEqual(self.write(),'recorded')
        self.k.calls.clear()
        self.assertEqual(self.r.cleanup(now=100),0)
        self.assertEqual(sum(n=='CreateToolhelp32Snapshot' for n,_ in self.k.calls),1)
        self.assertEqual(self.r.cleanup(now=100),0)
        self.assertEqual(sum(n=='CreateToolhelp32Snapshot' for n,_ in self.k.calls),2)
        self.assertIs(self.p.process.read(100).state,Presence.CURRENT)
        self.assertEqual(sum(n=='CreateToolhelp32Snapshot' for n,_ in self.k.calls),3)
        # Different deletion guards require separate vectors, not one mutation
        # changing all three values and accidentally proving only one predicate.
        for field in ('fileid','mtime','size'):
            original_read=self.r._read
            chosen=next(self.r.root.glob('*.json'))
            original=chosen.read_bytes();stamp=chosen.stat()
            real_validate=self.p.files.validate_file
            count=0
            def validation(path):
                nonlocal count
                value=real_validate(path)
                if path==chosen:
                    count+=1
                    if field=='fileid' and count>=3:return (value[0],value[1],value[2]+1)
                return value
            def read(path):
                record=original_read(path)
                if path==chosen:
                    if field=='mtime':os.utime(path,ns=(stamp.st_atime_ns,stamp.st_mtime_ns+1000000000))
                    if field=='size':
                        path.write_bytes(original+b' ')
                        os.utime(path,ns=(stamp.st_atime_ns,stamp.st_mtime_ns))
                return record
            with (patch.object(self.p.process,'same_generation',return_value=Presence.EXITED),
                  patch.object(self.r,'_paths',return_value=([chosen],True)),
                  patch.object(self.r,'_read',side_effect=read),
                  patch.object(self.p.files,'validate_file',side_effect=validation)):
                self.assertEqual(self.r.cleanup(now=100),0,field)
            self.assertTrue(chosen.exists(),field)
    def test_active_old_and_access_denied_are_not_age_deleted(self):
        self.assertEqual(self.write(),'recorded')
        path=next(self.r.root.glob('*.json'));os.utime(path,(1,1))
        self.assertEqual(self.r.cleanup(now=10**9),0)
        with patch.object(self.p.process,'same_generation',return_value=Presence.UNKNOWN):
            self.assertEqual(self.r.cleanup(now=10**9),0)
            rows=self.r.load(qualify=lambda _:True).records
            self.assertEqual(len(rows),1)
            self.assertFalse(rows[0]['qualified'])
            self.assertEqual(rows[0]['current'],'unknown')
        self.k.processes[100]=(0,134362090001712231,self.k.sid,False,'new')
        self.assertEqual(self.r.load().records,())
        self.assertEqual(self.r.cleanup(now=100),1)
    def test_unverified_garbage_future_time_and_no_age_authority(self):
        self.assertEqual(self.write(proof=None),'recorded')
        path=next(self.r.root.glob('*.json'));os.utime(path,(100,100))
        self.assertEqual(self.r.cleanup(now=100),0)
        self.assertEqual(self.r.cleanup(now=100+86400),1)
        self.assertEqual(self.write(proof=None),'recorded')
        path=next(self.r.root.glob('*.json'));os.utime(path,(10**9,10**9))
        self.assertEqual(self.r.cleanup(now=100+86400),0)
    def test_old_session_end_conflict_and_subagent_not_root(self):
        self.assertEqual(self.write(),'recorded')
        old=self.writer
        # Another CURRENT process/generation for same session is a conflict, not latest-wins.
        self.k.processes[101]=(100,134362090001712231,self.k.sid,False,'fixture')
        writer=ProcessIdentity('windows',101,'win-filetime','134362090001712231')
        self.assertEqual(self.write(writer=writer,proof=Proof(writer,'tui','subagent')),'recorded')
        result=self.r.load(qualify=lambda _:True)
        self.assertEqual(result.reason,'registration_ambiguous')
        self.assertFalse(any(x['qualified'] for x in result.records))
        self.assertEqual({x['sessionKind'] for x in result.records},{'root','subagent'})
        self.assertEqual(self.r.retire_exact('claude',self.id,old),1)
        rows=self.r.load(qualify=lambda _:True).records
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['agentProcess']['pid'],101)
        self.assertEqual(self.r.retire_exact('claude',self.id,old),0)
        self.assertEqual(len(self.r.load().records),1)
    def test_capacity_and_incomplete_scan_never_prove_unique(self):
        self.assertEqual(self.write(),'recorded')
        template=json.loads(next(self.r.root.glob('*.json')).read_text(encoding='utf-8'))
        for n in range(2,258):
            record={**template,'sessionId':f'019a0000-0000-7000-8000-{n:012x}'}
            self.p.files.atomic_write(self.r.root,json.dumps(record).encode(),name=key(record)+'.json',prefix='.r.')
        rows=self.r.load(qualify=lambda _:True)
        self.assertFalse(rows.complete)
        self.assertEqual(rows.reason,'registration_scan_incomplete')
        self.assertEqual(len(rows.records),256)
        self.assertFalse(any(x['qualified'] for x in rows.records))
        self.assertEqual(self.write(now=200),'registration_full')
        self.assertEqual(len(list(self.r.root.glob('*.json'))),257)
    def test_out_of_order_atomic_failures_and_budget(self):
        self.assertEqual(self.write(),'recorded')
        path=next(self.r.root.glob('*.json'));old=path.read_bytes()
        self.assertEqual(self.write(now=99),'older_observation')
        self.assertEqual(self.write(now=100),'older_observation')
        self.k.faults['MoveFileExW']=32
        with self.assertRaises(OSError): self.write(now=101)
        self.assertEqual(path.read_bytes(),old)
        self.assertEqual(self.write(now=101,deadline=time.monotonic()-1),'registration_deadline')
        self.assertEqual(len(list(self.r.root.glob('*.json'))),1)
    def test_entry_silent_invalid_and_overlong_input_no_external_work(self):
        self.k.current=os.getpid()
        self.k.processes[self.k.current]=(0,134362090001712230,self.k.sid,False,'python')
        raws=(b'{',b'x'*65537,b'{}',json.dumps(self.payload).encode()+b' '*65536,json.dumps(self.payload).encode())
        for index,raw in enumerate(raws):
            out,err=io.StringIO(),io.StringIO()
            stdin=type('Input',(),{'buffer':io.BytesIO(raw)})()
            with using_platform(self.p),patch.dict(os.environ,{'AB_STATE_DIR':str(self.root)}),patch.object(sys,'stdin',stdin),redirect_stdout(out),redirect_stderr(err):
                self.assertEqual(main(),0)
            self.assertEqual((out.getvalue(),err.getvalue()),('',''))
            self.assertEqual(len(self.r.load().records),1 if index==len(raws)-1 else 0)
        self.assertEqual(len(self.r.load().records),1)
        # Test S's disabled contract without loading POSIX F/L on Windows.
        with patch('test_bridge_registration.make_platform',side_effect=AssertionError('must not import POSIX backend')):
            disabled=Registry(self.root,replace(self.p,name='linux'))
        self.assertEqual(disabled.cleanup(now=10**9),0)
        self.assertEqual(disabled.load().reason,'registration_disabled')
        self.assertEqual(disabled.write({},provider='claude',writer=self.writer,now=1),'disabled')
        code='import sys; import agentstatus_bridge.registration; assert not any("agentstatus_bridge."+n in sys.modules for n in ("cli","worker","doctor","store"))'
        # 子进程不继承本进程对 sys.path 的修改（Windows CI 只在进程内加 src）；显式指向与本测试同一份包
        src=str(Path(sys.modules['agentstatus_bridge'].__file__).resolve().parents[1])
        env={**os.environ,'PYTHONPATH':os.pathsep.join(filter(None,(src,os.environ.get('PYTHONPATH'))))}
        done=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,encoding='utf-8',env=env)
        self.assertEqual(done.returncode,0,done.stderr)


if __name__=='__main__': unittest.main()

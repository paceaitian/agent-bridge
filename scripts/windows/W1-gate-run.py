"""Windows only, private fixture gates. No agent launch/real provider connection.
Prepared on Linux; NOT RUN on Windows until an authorized native session does so.
"""
import argparse
from contextlib import redirect_stdout,redirect_stderr
from dataclasses import asdict
import ctypes as C
import gc
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid
from typing import Any, cast
from dataclasses import replace
sys.path.insert(0,str(Path(__file__).resolve().parent))  # also when PS cleanup uses -I
from w1_gate_native import read_shared, warmup_native


def config(root) -> tuple[Any, Any]:
    if sys.platform!='win32' or sys.version_info<(3,12):
        raise RuntimeError('windows_cpython312_required')
    if not root.name.startswith('ab-w1-') or root.is_symlink():
        raise RuntimeError('wrong_private_root')
    sys.path.insert(0,str(root/'source'/'src'))
    from agentstatus_bridge.platforms.windows.api import WinApi
    from agentstatus_bridge.platforms.windows.files import WindowsPaths
    from agentstatus_bridge.platforms.factory import make_platform
    api=WinApi();api.current_token()
    p=make_platform('windows',win_api=api)
    with p.files.lease(root): pass
    os.environ['AB_STATE_DIR']=str(root/'state')
    os.environ['AB_COMMAND']='agent-bridge'
    os.environ.pop('AB_BINDING',None)
    return api,p


def warmup_stdlib(root):
    """Three fixed additional first-uses; no retry-to-stability.

    config() already imported the bridge and performed one token/lease before
    the baseline. This list differs from the unversioned r2 control scripts
    (no recv/timeout-select); absorbing all +5 remains UNVERIFIED, possibly
    a false red at the next native gate. Package calls are not added here.
    """
    with subprocess.Popen([sys.executable,'-I','-B','-S','-c','pass'],stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True) as proc:
        try:
            assert proc.wait(timeout=10)==0
        except BaseException:
            # Only the process created by this Popen, never a PID lookup.
            if proc.poll() is None:proc.kill()
            proc.wait(timeout=5)
            raise
        finally:getattr(proc, '_handle').Close()
    address=('unix',str(root/'warm.sock'))
    allowed.add(address)
    try:operations=warmup_native(root)
    finally:allowed.discard(address)
    return {'operations':['subprocess.Popen(current-python,-I,-B,-S,-c,pass)+wait+close']+operations,
            'basis':'W1 gate r2 runs[1/3] independent stdlib/raw-client controls',
            'packageWarmup':False}


def measured_round(body, handles, cleanup):
    before=handles()
    try:body()
    finally:
        cleanup()
        gc.collect()
    after=handles()
    return {'before':before,'after':after,'delta':after-before,'passed':after-before==0}


def read_fixture_frame(stream):
    data=b''
    # At most eight one-byte fragments; EOF must fail, never spin indefinitely.
    for _ in range(8):
        part=stream.recv(min(2,8-len(data)))
        assert part, 'fixture_eof_before_frame'
        data+=part
        if len(data)==8:break
    assert data==b'abc\nhalf'
    return data


def remove_fixture_socket(api,files,path):
    """Only our exact bound rendezvous, never generic reparse cleanup."""
    files.validate_socket(path)
    api.delete(str(path))


def cleanup_reparse_tree(root):
    # lstat/scandir, never recurse through ANY reparse directory. Only the exact
    # AF_UNIX non-directory tag is a removable rendezvous, never a junction.
    stack=[root];sockets=[];unknown=0
    if root.lstat().st_file_attributes & 0x400:
        return {'safe':False,'removedSockets':0,'unknownReparse':1}
    while stack:
        directory=stack.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                info=cast(Any,entry.stat(follow_symlinks=False))
                if info.st_file_attributes & 0x400:
                    if info.st_reparse_tag==0x80000023 and not info.st_file_attributes & 0x10:
                        sockets.append(Path(entry.path))
                    else:unknown+=1
                elif info.st_file_attributes & 0x10:stack.append(Path(entry.path))
    if unknown:return {'safe':False,'removedSockets':0,'unknownReparse':unknown}
    for path in sockets:
        info=path.lstat()
        if info.st_reparse_tag!=0x80000023 or info.st_file_attributes & 0x10:
            raise RuntimeError('cleanup_reparse_changed')
        path.unlink()
    return {'safe':True,'removedSockets':len(sockets),'unknownReparse':0}


allowed=set()
provider_attempts=0
class GateBoundary(BaseException): pass
def boundary(event,args):
    global provider_attempts
    if event=='socket.connect' or (event=='agent_bridge.windows.connect' and (args[0],args[1]) not in allowed):
        provider_attempts+=1
        raise GateBoundary('production_connection_forbidden')


def birth(api,pid):
    from agentstatus_bridge.platforms.types import ProcessIdentity
    return ProcessIdentity('windows',pid,'win-filetime',str(api.process(pid).birth))


def own_birth(api,proc):
    # Own Popen kernel handle remains valid even if a very short probe exited.
    from agentstatus_bridge.platforms.windows.abi import FILETIME
    from agentstatus_bridge.platforms.types import ProcessIdentity
    times=[FILETIME() for _ in range(4)]
    api.check(api.k.GetProcessTimes(int(proc._handle),*(C.byref(t) for t in times)))
    return ProcessIdentity('windows',proc.pid,'win-filetime',str(times[0].number()))


def write_ready(p,root,name,value):
    p.files.atomic_write(root,json.dumps(value).encode(),name=name,prefix='.ready.')


def until_file(path,timeout=5):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        try:return json.loads(read_shared(path))
        except FileNotFoundError:pass
        time.sleep(.02)
    raise TimeoutError('fixture_ready_timeout')


def wait_stop(api,p,root,timeout=12):
    from agentstatus_bridge.platforms.windows.stop import stop_requested
    identity=birth(api,os.getpid());deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if stop_requested(p.files,root,identity): return
        time.sleep(.02)
    raise TimeoutError('fixture_stop_timeout')


def child(root,kind,mode='',peer_pid=0,peer_birth=''):
    api,p=config(root)
    from agentstatus_bridge.platforms.types import ProcessIdentity
    from agentstatus_bridge.platforms.windows.io import WinIO,unix_address
    from agentstatus_bridge.platforms.windows.streams import PipeListener
    if kind=='fake-kernel':
        import unittest
        sys.path.insert(0,str(root/'source'/'tests'))
        suite=unittest.defaultTestLoader.loadTestsFromNames(
            ['test_bridge_windows','test_bridge_windows_streams','test_bridge_registration'])
        class Result(unittest.TextTestResult):
            def __init__(self,*args):super().__init__(*args);self.cases=[]
            def addSuccess(self,test):
                super().addSuccess(test)
                self.cases.append({'test':unittest.TestCase.id(test),'outcome':'ok'})
        result=unittest.TextTestRunner(stream=io.StringIO(),resultclass=Result).run(suite)
        doc={'completedMarker':True,'testsRun':result.testsRun,'failures':len(result.failures),
             'errors':len(result.errors),'skipped':len(result.skipped),'cases':cast(Result,result).cases}
        print(json.dumps(doc))
        if not result.wasSuccessful() or result.skipped:raise SystemExit(1)
        return
    if kind=='local-core':
        from agentstatus_bridge import cli
        from agentstatus_bridge.platforms.factory import using_platform
        with using_platform(p),redirect_stdout(io.StringIO()),redirect_stderr(io.StringIO()):
            try:cli.main(['--help'])
            except SystemExit as e:assert e.code==0
            assert cli.main(['doctor','--json'])==0
            assert cli.main(['tasks','--json'])==0
        print(json.dumps({'python':sys.version.split()[0],'localCore':True}))
        return
    if kind in ('lock-probe','lock-holder','worker'):
        handle=p.lifecycle.open_lock(root/'fixture.lock')
        got=False
        try:
            try: p.lifecycle.try_lock(handle,shared=mode=='shared');got=True
            except BlockingIOError: pass
            if kind=='lock-probe': print(json.dumps({'locked':got}));return
            write_ready(p,root,'ready-'+kind+'.json',{'locked':got,**api.context()})
            if got: wait_stop(api,p,root)
        finally:
            if got:p.lifecycle.unlock(handle)
            p.lifecycle.close_lock(handle)
        return
    expected=ProcessIdentity('windows',peer_pid,'win-filetime',peer_birth)
    if kind=='pipe':
        name='\\\\.\\pipe\\'+root.name+'-fixture'
        listener=PipeListener(api,p.files,root,name)
        stream=None
        try:
            write_ready(p,root,'ready-pipe.json',{'ready':True})
            stream=listener.accept(expected,5)
            stream.sendall(b'ab');stream.sendall(b'c\nhalf')
            wait_stop(api,p,root)
        finally:
            if stream:stream.close()
            listener.close()
    elif kind=='unix':
        io_=WinIO(api);sock=io_.socket();client=None
        path=root/'s';bound=False
        try:
            with p.files.lease(root):
                address=unix_address(str(path))
                if api.ws.bind(sock,C.byref(address),C.sizeof(address)):
                    raise OSError('fixture_listen_failed')
                bound=True
                if api.ws.listen(sock,1):raise OSError('fixture_listen_failed')
                write_ready(p,root,'ready-unix.json',{'ready':True})
                io_.wait_socket(sock,time.monotonic()+5,write=False)
                client=api.ws.accept(sock,None,None)
                if client==C.c_size_t(-1).value:raise OSError('fixture_accept_failed')
                api.check(api.k.SetHandleInformation(client,1,0))
                nonblock=C.c_uint32(1)
                if api.ws.ioctlsocket(client,-2147195266,C.byref(nonblock)):raise OSError('nonblock_failed')
                actual=birth(api,io_.peer_pid(client))
                assert actual==expected
                assert api.process(actual.pid).token==api.current_token()
                io_.socket_write(client,b'ab',time.monotonic()+1)
                io_.socket_write(client,b'c\nhalf',time.monotonic()+1)
                wait_stop(api,p,root)
        finally:
            if client not in (None,C.c_size_t(-1).value):api.ws.closesocket(client)
            io_.close_socket(sock)
            if bound:remove_fixture_socket(api,p.files,path)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--context',choices=('desktop','tool-job','rmux','ssh','unverified'),default='unverified')
    parser.add_argument('--source-sha',default='')
    parser.add_argument('--second-python')
    parser.add_argument('--cleanup-reparse',action='store_true')
    parser.add_argument('--child',choices=('lock-probe','lock-holder','worker','pipe','unix','local-core','fake-kernel'))
    parser.add_argument('--mode',default='')
    parser.add_argument('--peer-pid',type=int,default=0)
    parser.add_argument('--peer-birth',default='')
    args=parser.parse_args();root=args.root
    if args.cleanup_reparse:
        if not root.name.startswith('ab-w1-') or not root.is_absolute():raise RuntimeError('wrong_private_root')
        doc=cleanup_reparse_tree(root);print(json.dumps(doc));return 0 if doc['safe'] else 1
    # Fake DLL suite installs bridge_platform_guard itself; our real-fixture
    # allowlist must not intercept its intentional guard-negative audit events.
    if args.child!='fake-kernel':sys.addaudithook(boundary)
    if args.child:
        child(root,args.child,args.mode,args.peer_pid,args.peer_birth);return 0
    api,p=config(root)
    from agentstatus_bridge import cli,summary,worker
    from agentstatus_bridge.store import Store
    from agentstatus_bridge.platforms.factory import using_platform
    from agentstatus_bridge.platforms.windows.streams import WinsockStream,PipeStream
    from agentstatus_bridge.platforms.windows.io import reap
    from agentstatus_bridge.platforms.windows.stop import request_stop
    from agentstatus_bridge.registration import Registry,key
    results=[];children=[];round_number=0
    def run(name,fn):
        try:
            evidence=fn()
            results.append({'id':name,'status':'PASS','evidence':evidence or {}})
        except (Exception,GateBoundary) as exc:
            row={'id':name,'status':'FAIL','reason':type(exc).__name__}
            if isinstance(getattr(exc,'winerror',None),int):row['winerror']=getattr(exc,'winerror')
            results.append(row)
    def spawn(kind,mode='',python=None):
        # Repeated rounds cannot consume a previous process's ready marker.
        ready=root/('ready-'+kind+'.json')
        if ready.exists():ready.unlink()
        argv=[python or sys.executable,str(Path(__file__)), '--root',str(root),'--child',kind,'--mode',mode,
              '--peer-pid',str(os.getpid()),'--peer-birth',str(api.process(os.getpid()).birth)]
        proc=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                              env=p.lifecycle.worker_environment(os.environ),close_fds=True)
        try: identity=own_birth(api,proc)
        except OSError:
            if proc.poll() is None:proc.terminate()
            proc.wait(timeout=5)
            if proc.stdout:proc.stdout.close()
            getattr(proc, '_handle').Close()
            raise
        children.append((proc,identity))
        return proc,identity
    def stop(proc,identity,force=False):
        if proc.poll() is None:
            assert birth(api,proc.pid)==identity
            if force:proc.terminate()  # ONLY our Popen and exact generation
            else:request_stop(p.files,root,identity)
        proc.wait(timeout=5)
        if proc.stdout:proc.stdout.close()
        proc._handle.Close()  # exactly the Popen handle we created, after wait
        if (proc,identity) in children:children.remove((proc,identity))
    def local_core():
        assert sys.version_info[:3]==(3,12,9), 'primary_interpreter_changed'
        with using_platform(p),redirect_stdout(io.StringIO()),redirect_stderr(io.StringIO()):
            try:cli.main(['--help'])
            except SystemExit as e:assert e.code==0
            assert cli.main(['doctor','--json'])==0
            with Store.open(root/'state') as store:
                assert store._conn.execute('PRAGMA journal_mode').fetchone()[0]=='wal'
                summary.publish(store,root/'state',force=True)
                p.files.validate_database(root/'state'/'bridge.sqlite3')
                p.files.validate_file(root/'state'/'summary.json')
                # WAL/SHM may disappear on close. Evidence must be taken HERE.
                derived={}
                for name in ('bridge.sqlite3','bridge.sqlite3-wal','bridge.sqlite3-shm','summary.json','summary.lock'):
                    target=root/'state'/name
                    assert target.is_file()
                    p.files.validate_file(target)
                    derived[name]={'present':True,'privateValidated':True}
            assert cli.main(['tasks','--json'])==0
            assert cli.main(['summary','--refresh','--json'])==0
            assert cli.main(['send','--to','fixture','-m','synthetic'])==9
            assert worker.default_transports()=={}
        return {'python':sys.version.split()[0],'localStore':True,'providerEnabled':False,'wheelReleaseGate':'NOT_RUN_W1_7',
                'derivedFilesWhileStoreOpen':derived}
    def locks():
        for left,right,allowed_ in [(True,True,True),(True,False,False),(False,True,False),(False,False,False)]:
            h=p.lifecycle.open_lock(root/'fixture.lock')
            try:
                p.lifecycle.try_lock(h,shared=left)
                proc,identity=spawn('lock-probe','shared' if right else 'exclusive')
                stdout,_=proc.communicate(timeout=5)
                assert proc.returncode==0 and json.loads(stdout)['locked']==allowed_
                stop(proc,identity)
            finally:p.lifecycle.unlock(h);p.lifecycle.close_lock(h)
        proc,identity=spawn('lock-holder')
        assert until_file(root/'ready-lock-holder.json')['locked']
        stop(proc,identity,True)
        deadline=time.monotonic()+3;got=False
        while time.monotonic()<deadline:
            h=p.lifecycle.open_lock(root/'fixture.lock')
            try:
                try:p.lifecycle.try_lock(h);got=True;p.lifecycle.unlock(h)
                except BlockingIOError:time.sleep(.02)
            finally:p.lifecycle.close_lock(h)
            if got:break
        assert got
        return {'matrix':4,'crashReleased':True}
    def file_negatives():
        for path in (root/'wide',root/'junction',Path(r'\\invalid\share\never-connect')):
            rejected=False
            try:p.files.ensure_private_dir(path)
            except OSError:rejected=True
            assert rejected
        leaf=root/'pin';p.files.ensure_private_dir(leaf)
        with p.files.lease(leaf):
            denied=False
            try:leaf.rename(root/'pin-moved')
            except OSError:denied=True
            assert denied and leaf.exists()
        p.files.atomic_write(root,b'old',name='atomic.json',prefix='.a.')
        h=api.open_file(str(root/'atomic.json'))
        try:
            rejected=False
            try:p.files.atomic_write(root,b'new',name='atomic.json',prefix='.a.')
            except OSError:rejected=True
            assert rejected and (root/'atomic.json').read_bytes()==b'old'
        finally:api.close(h)
        return {'wideRejected':True,'reparseRejected':True,'uncRejectedBeforeIO':True,'leasePreventsRename':True,'replacePreservesOld':True}
    def streams(kind):
        proc,identity=spawn(kind)
        until_file(root/('ready-'+kind+'.json'))
        address=str(root/'s') if kind=='unix' else '\\\\.\\pipe\\'+root.name+'-fixture'
        allowed.add((kind,address))
        stream=None
        try:
            # Both real API negative paths, without bypassing file validation.
            for field in ('pid','generation_value'):
                from agentstatus_bridge.platforms.types import ProcessIdentity
                rejected=False;bad=None
                try:
                    expected=(replace(identity,pid=os.getpid()) if field=='pid'
                              else replace(identity,generation_value=str(int(identity.generation_value)-1)))
                    bad=(WinsockStream(api,p.files,Path(address),expected) if kind=='unix'
                         else PipeStream(api,p.files,root,address,expected))
                except OSError:rejected=True
                finally:
                    if bad:bad.close()
                # A single-connection fixture may already have accepted the
                # rejected client; restart only our own fixture for next case.
                assert rejected
                stop(proc,identity,True)
                if kind=='unix' and (root/'s').exists():remove_fixture_socket(api,p.files,root/'s')
                proc,identity=spawn(kind)
                until_file(root/('ready-'+kind+'.json'))
            stream=(WinsockStream(api,p.files,Path(address),identity) if kind=='unix'
                    else PipeStream(api,p.files,root,address,identity))
            read_fixture_frame(stream)
            stream.settimeout(.05)
            expired=False
            try:stream.recv(1)
            except TimeoutError:expired=True
            assert expired
        finally:
            if stream:stream.close()
            stop(proc,identity)
            allowed.discard((kind,address))
        assert reap()
        if kind=='unix':assert not (root/'s').exists()
        return {'twoProcesses':True,'peerGenerationAndToken':True,'partsReassembled':True,'halfLineTimeout':True,
                'cancelDrained':True,'wrongPidAndGenerationRejected':True,'socketRemoved':kind=='unix'}
    def spawner():
        # Own small script, production spawner still disabled; Python/Job flags from backend.
        stub=b"from pathlib import Path\nimport runpy\nn=runpy.run_path(str(Path(__file__).with_name('W1-gate-run.py')))\nn['child'](Path(__file__).parent,'worker')\n"
        p.files.atomic_write(root,stub,name='fixture-worker.py',prefix='.w.')
        ready=root/'ready-worker.json'
        if ready.exists():ready.unlink()
        proc=p.lifecycle.spawn_fixture(root/'fixture-worker.py',root)
        identity=own_birth(api,proc);children.append((proc,identity))
        doc=until_file(root/'ready-worker.json')
        assert doc['locked'] and doc['consoleDetached'] and doc['outlivesJob'] is False
        stop(proc,identity)
        return {'context':args.context,'consoleDetached':doc['consoleDetached'],'inJob':doc['inJob'],
                'outlivesJob':False,'cooperativeStop':True,'actualPaneClose':'NOT_RUN_FORBIDDEN'}
    def registration():
        reg=Registry(root/('registration-round-'+str(round_number)),p);writer=birth(api,os.getpid())
        payload={'hook_event_name':'SessionStart','session_id':str(uuid.uuid4()),'prompt':'PRIVATE_CANARY','token':'PRIVATE_CANARY'}
        assert reg.write(payload,provider='claude',writer=writer,now=time.time())=='recorded'
        assert reg.root==root/('registration-round-'+str(round_number))/'registrations'/'v1'
        assert len(list(reg.root.glob('*.json')))==1
        candidates=reg.load()
        assert len(candidates.records)==1 and not candidates.records[0]['qualified']
        assert candidates.records[0]['sessionKind']=='unknown'
        for record in reg.root.glob('*.json'):
            assert 'PRIVATE_CANARY' not in record.read_text()
            p.files.validate_file(record)
        # Independently construct reader fixtures; not a qualified real Claude hook.
        template=dict(candidates.records[0])
        template.pop('current');template.pop('qualified')
        ready=root/'ready-lock-holder.json'
        if ready.exists():ready.unlink()
        proc,owner=spawn('lock-holder')
        until_file(ready)
        record={**template,'sessionId':str(uuid.uuid4()),'source':'controlled-fixture',
                'agentProcess':asdict(owner),'ownerRole':'tui','sessionKind':'subagent'}
        p.files.atomic_write(reg.root,json.dumps(record).encode(),name=key(record)+'.json',prefix='.r.')
        rows=reg.load().records
        assert any(x['sessionKind']=='subagent' and x['current']=='current' for x in rows)
        stop(proc,owner)
        assert not any(x['sessionKind']=='subagent' for x in reg.load().records)
        assert reg.cleanup(now=time.time())>=1
        return {'validUnverifiedProjection':True,'noSelfAuthorization':True,'privateFiles':True,'realExitedGenerationRemoved':True,
                'qualifiedClaudeHook':'NOT_RUN_W3','codexPaneAttribution':'UNSUPPORTED'}
    def second_python():
        done=subprocess.run([args.second_python,str(Path(__file__)),'--root',str(root),'--child','local-core'],
                            env=p.lifecycle.worker_environment(os.environ),stdin=subprocess.DEVNULL,
                            capture_output=True,timeout=30,check=False)
        assert done.returncode==0
        doc=json.loads(done.stdout)
        assert doc['localCore'] and doc['python']=='3.13.11'
        return doc
    def fake_kernel():
        done=subprocess.run([sys.executable,str(Path(__file__)),'--root',str(root),'--child','fake-kernel'],
                            env=p.lifecycle.worker_environment(os.environ),stdin=subprocess.DEVNULL,
                            capture_output=True,timeout=120,check=False)
        doc=json.loads(done.stdout)
        assert doc['completedMarker'] and doc['testsRun']>=38
        assert doc['errors']==0 and doc['failures']==0 and doc['skipped']==0 and done.returncode==0
        assert sum(x['test'].startswith('test_bridge_registration.') for x in doc['cases'])==10
        return doc
    def private_job():
        # Only a new unnamed Job containing our own fixture; never the pane/tool Job.
        class Limits(C.Structure):
            _fields_=[('process_time',C.c_int64),('job_time',C.c_int64),('flags',C.c_uint32),
                      ('min_ws',C.c_size_t),('max_ws',C.c_size_t),('active',C.c_uint32),
                      ('affinity',C.c_size_t),('priority',C.c_uint32),('scheduling',C.c_uint32)]
        class Extended(C.Structure):
            _fields_=[('basic',Limits),('io',C.c_uint64*6),('memory',C.c_size_t*4)]
        create=api.k.CreateJobObjectW;create.argtypes=[C.c_void_p,C.c_void_p];create.restype=C.c_void_p
        setinfo=api.k.SetInformationJobObject;setinfo.argtypes=[C.c_void_p,C.c_int,C.c_void_p,C.c_uint32];setinfo.restype=C.c_int32
        assign=api.k.AssignProcessToJobObject;assign.argtypes=[C.c_void_p,C.c_void_p];assign.restype=C.c_int32
        handle=api.handle(create(None,None));opened=None
        try:
            info=Extended();info.basic.flags=0x2000
            api.check(setinfo(handle,9,C.byref(info),C.sizeof(info)))
            ready=root/'ready-lock-holder.json'
            if ready.exists():ready.unlink()
            proc,identity=spawn('lock-holder');until_file(ready)
            assert birth(api,proc.pid)==identity
            opened=api.handle(api.k.OpenProcess(0x1101,False,proc.pid))
            api.check(assign(handle,opened))
            api.close(handle);handle=None
            proc.wait(timeout=5)
            stop(proc,identity)
            assert proc.returncode is not None
            return {'ownKillOnJobClose':True,'paneJobChanged':False,'breakaway':False}
        finally:
            if opened is not None:api.close(opened)
            if handle is not None:api.close(handle)
    def handles():
        fn=api.k.GetProcessHandleCount;fn.argtypes=[C.c_void_p,C.c_void_p];fn.restype=C.c_int32
        n=C.c_uint32();api.check(fn(api.k.GetCurrentProcess(),C.byref(n)))
        return n.value
    def cleanup_children():
        for proc,identity in list(children):
            stop(proc,identity,True)
        assert reap()
    def round_body():
        run('G1-local-core',local_core)
        run('G2-lock-matrix-crash',locks)
        run('G2-acl-reparse-sharing',file_negatives)
        run('G3-winsock',lambda:streams('unix'))
        run('G3-pipe',lambda:streams('pipe'))
        run('G4-fixture-worker',spawner)
        run('G4-private-kill-job',private_job)
        run('G5-registration',registration)
        if args.second_python:run('G1-second-python',second_python)
        else:results.append({'id':'G1-second-python','status':'NOT_RUN','reason':'supply_second_supported_interpreter'})
    resource_rounds=[]
    try:
        before=handles();warm=warmup_stdlib(root);gc.collect();warm['delta']=handles()-before
        results.append({'id':'G3-stdlib-warmup','status':'OBSERVED','evidence':warm})
        for round_number in range(1,4):
            start=len(results)
            resource=measured_round(round_body,handles,cleanup_children)
            resource_rounds.append(resource)
            for row in results[start:]:row['round']=round_number
            results.append({'id':'G3-handle-round','round':round_number,
                            'status':'PASS' if resource['passed'] else 'FAIL','evidence':resource})
        # False precision forbidden: these need the native agent's bounded supplementary cases.
        for name in ('G2-existing-owner-mismatch','G3-error-branches-not-safe-to-create','G5-real-qualified-Claude-hook'):
            results.append({'id':name,'status':'NOT_RUN','reason':'follow_brief_supplementary_steps'})
        run('G-fake-kernel-tests',fake_kernel)
    finally:
        alive=0
        for proc,identity in list(children):
            try:stop(proc,identity,True)
            except Exception:alive+=int(proc.poll() is None)
        children.clear();gc.collect()
        results.append({'id':'G3-handle-count','status':'PASS' if len(resource_rounds)>=3 and all(x['passed'] for x in resource_rounds) else 'FAIL',
                        'evidence':{'rounds':resource_rounds,'requiredRounds':3,'allowedDelta':0}})
        results.append({'id':'G6-boundary','status':'PASS' if provider_attempts==0 and alive==0 else 'FAIL',
                        'evidence':{'providerDeliveries':0,'unregisteredConnectAttempts':provider_attempts,'ownedLive':alive,
                                    'rmuxWrites':0,'servicesRestarted':0}})
        doc={'schema':1,'sourceSha256':args.source_sha,'context':args.context,'rootName':root.name,'results':results,
             'conclusion':'PARTIAL_QUALIFICATION','cleanup':'see W1-gate-cleanup.jsonl'}
        if args.output is None:raise RuntimeError('output_required')
        args.output.mkdir(parents=True,exist_ok=True)
        out=args.output/'W1-gate-results.json'
        history=json.loads(out.read_text()) if out.exists() else {'schema':1,'runs':[]}
        history['runs'].append(doc)
        out.write_text(json.dumps(history,ensure_ascii=False,indent=2)+'\n')
        lines=['# W1 Windows 实机门结果','', '每次运行保留在 JSON runs；NOT_RUN 不是 PASS。', '']
        for i,entry in enumerate(history['runs'],1):
            lines += [f'## Run {i}: {entry["context"]}', '']
            lines += [f'- {r["id"]}: {r["status"]}' for r in entry['results']]
        (args.output/'W1-gate-results.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
        print(json.dumps({'conclusion':doc['conclusion'],'failures':sum(r['status']=='FAIL' for r in results),
                          'notRun':sum(r['status']=='NOT_RUN' for r in results),'providerDeliveries':0}))
    return int(any(r['status']=='FAIL' for r in results))


if __name__=='__main__':
    try:raise SystemExit(main())
    except (Exception,GateBoundary) as error:
        print(json.dumps({'status':'FAIL','reason':type(error).__name__}))
        raise SystemExit(1)

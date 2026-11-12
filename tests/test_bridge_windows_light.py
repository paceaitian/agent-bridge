"""W2 B2 real CLI/SDK fake coverage; zero real daemon or process launches."""
from dataclasses import replace
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_bridge_windows_delivery as fixture
from test_bridge_windows_discovery import uuid
from agentstatus_bridge import cli
from agentstatus_bridge.model import Delivery, Flow, Provider
from agentstatus_bridge.store import Store
from agentstatus_bridge.transports.codex_native import NativeFailure
from agentstatus_bridge.platforms.windows import commands as B, codex_discovery as D
from agentstatus_bridge.platforms.windows.local_transport import IdentityEvidence


class LightTests(unittest.TestCase):
    setUp = fixture.DeliveryTests.setUp
    rebuild = fixture.DeliveryTests.rebuild
    scope = fixture.DeliveryTests.scope
    chain = fixture.DeliveryTests.chain
    run_cli = fixture.DeliveryTests.run_cli
    target = fixture.DeliveryTests.target

    def initialized(self):
        return sum(m['method']=='initialize' for m in self.k.messages)

    def test_all_six_commands_authenticate_without_application_bytes(self):
        env=self.chain()
        self.assertEqual(B.LIGHT, {'report','accept','close','pause','cancel','resume'})
        with self.scope(),patch.dict(os.environ,env),patch('agentstatus_bridge.platforms.windows.caller.os.getpid',return_value=100):
            for action in sorted(B.LIGHT):
                before=sum(n=='connect' for n,_ in self.k.calls)
                with B.scope(SimpleNamespace(command=action)):
                    proof=B.evidence()
                    self.assertIsInstance(proof,IdentityEvidence)
                    self.assertEqual(B.caller().endpoint.ref.native_id,uuid(1))
                    self.assertEqual(proof.daemon,(200,str(self.k.processes[200][1])))
                    self.assertEqual(B.endpoints(),[])
                self.assertEqual(sum(n=='connect' for n,_ in self.k.calls),before+1)
                self.assertEqual(self.k.socket_out,b'')
                self.assertEqual(self.k.messages,[])
                self.assertEqual(self.k.handles,{})

    def test_report_succeeds_with_empty_or_changing_loaded_and_no_initialize(self):
        env=self.chain()
        with (self.scope(),patch.dict(os.environ,env),patch('agentstatus_bridge.platforms.windows.caller.os.getpid',return_value=100),
              patch.object(cli,'_revive_worker'),patch.object(cli,'_start_worker',return_value=False)):
            target=self.target()
            for changed in ([],[uuid(2),uuid(3)]):
                with Store.open(self.state) as store:
                    task,attempt=store.create_task(title='fixture',flow=Flow.HANDOFF,origin=None,origin_class=None,
                        reviewer=None,target=target.ref,body='fixture',refs=[],now=1000)
                    store.begin_send(attempt.id,now=1001,pid=100,start_ticks='1')
                    store.finish_send(attempt.id,delivery=Delivery.QUEUED,reason='fixture',provider_ref=uuid(900),detail={},now=1002)
                self.k.loaded=changed
                self.k.messages.clear();self.k.socket_out.clear()
                self.k.after=lambda m:self.k.loaded.reverse()
                code,out,err=self.run_cli('report',task.id,'--ack','--json')
                self.assertEqual(code,0,(out,err))
                self.assertEqual(self.initialized(),0)
                self.assertEqual(self.k.socket_out,b'')

    def test_light_path_still_rejects_subagent_nearest_agent_and_peer(self):
        for case in ('subagent','nearest','peer'):
            self.rebuild();env=self.chain()
            if case=='subagent':env['CODEX_SESSION_ID']=uuid(2)
            if case=='nearest':
                row=self.k.processes[201];self.k.processes[201]=(*row[:4],'codex.exe')
            if case=='peer':self.k.peer=100
            with self.scope(),patch.dict(os.environ,env),patch('agentstatus_bridge.platforms.windows.caller.os.getpid',return_value=100):
                with self.assertRaisesRegex(NativeFailure,'reporter_is_subagent' if case=='subagent' else 'caller_unattributed'):
                    with B.scope(SimpleNamespace(command='report')):pass
                self.assertEqual(self.initialized(),0)
                self.assertEqual(self.k.socket_out,b'')

    def test_light_task_check_compares_root_and_business_identity_remains(self):
        env=self.chain()
        with self.scope(),patch.dict(os.environ,env),patch('agentstatus_bridge.platforms.windows.caller.os.getpid',return_value=100):
            with B.scope(SimpleNamespace(command='close')):
                own=B.caller().endpoint.ref
                B.check_task(SimpleNamespace(origin=own,reviewer=None),[SimpleNamespace(target=own)])
                for root in (None,'b'*64):
                    with self.assertRaisesRegex(NativeFailure,'target_root_changed'):
                        B.check_task(SimpleNamespace(origin=own,reviewer=None),[SimpleNamespace(target=replace(own,data_root=root))])
                task=SimpleNamespace(origin=replace(own,native_id=uuid(2)))
                self.assertFalse(cli._may_decide(B.caller(),task))

    def test_send_uses_one_discovery_including_review_target(self):
        env=self.chain();self.k.loaded=[uuid(1),uuid(2),uuid(3)]
        with (self.scope(),patch.dict(os.environ,env),patch('agentstatus_bridge.platforms.windows.caller.os.getpid',return_value=100),
              patch.object(cli,'_start_worker',return_value=False),patch.object(cli,'_worker_up',return_value=False),
              patch.object(cli,'_revive_worker')):
            code,out,err=self.run_cli('send','--to',uuid(2),'--review-by',uuid(3),'-m','fixture','--no-wait','--json')
            self.assertEqual(code,6,(out,err))
            self.assertEqual(self.initialized(),1)
            with Store.open(self.state) as store:
                task=store.list_tasks()[0]
                self.assertEqual(task.reviewer.native_id,uuid(3))
                self.assertEqual(store.attempts(task.id)[0].target.native_id,uuid(2))

    def test_changed_loaded_uses_union_for_names_and_prefixes(self):
        self.k.loaded=[uuid(1),uuid(2)]
        self.k.metadata={uuid(1):{'id':uuid(1),'source':'cli','name':'stable'},
                         uuid(2):{'id':uuid(2),'source':'cli','name':'collision'},
                         uuid(3):{'id':uuid(3),'source':'cli','name':'collision'}}
        self.k.after=lambda m:self.k.loaded.__setitem__(slice(None),[uuid(1),uuid(3)]) if m['method']=='thread/read' else None
        with self.scope():result=D.discover(self.p.transport)
        self.assertTrue(result.complete)
        self.assertEqual(result.loaded_total,3)
        self.assertEqual(result.select('stable').thread,uuid(1))
        self.assertEqual(result.select(uuid(1)).thread,uuid(1))
        for value in (uuid(2),uuid(3)):
            with self.assertRaisesRegex(NativeFailure,'target_changed'):result.select(value)
        # 名字与显式 id: 前缀都按两次 loaded 的并集判歧义；裸 '00000000' 只按名字，找不到（§91.2.1）
        for value in ('collision','id:00000000'):
            with self.assertRaisesRegex(NativeFailure,'target_ambiguous'):result.select(value)
        with self.assertRaisesRegex(NativeFailure,'target_not_found'):result.select('00000000')
        self.assertEqual(result.native_reads,3)
        self.assertEqual(self.initialized(),1)
        sampler=D.WorkerDiscovery(self.p.transport);sampler.result=result
        self.assertFalse(sampler.complete())

    def test_union_supplement_shares_the_original_native_budget(self):
        self.k.loaded=[uuid(i) for i in range(1,33)]
        self.k.after=lambda m:self.k.loaded.__setitem__(slice(None),[uuid(i) for i in range(1,35)]) if m['method']=='thread/read' else None
        with self.scope():result=D.discover(self.p.transport)
        self.assertTrue(result.complete)
        self.assertEqual(result.loaded_total,34)
        self.assertEqual(result.native_reads,32)
        self.assertTrue(result.native_read_budget_hit)
        self.assertEqual(sum(m['method']=='thread/read' for m in self.k.messages),32)
        self.assertEqual(result.select(uuid(1)).thread,uuid(1))

    def test_union_over_4096_rejected_even_when_each_sample_fits(self):
        # Both real paginated samples meet the limit; only their union exceeds it.
        self.k.loaded=[uuid(i) for i in range(1,4097)]
        self.k.after=lambda m:self.k.loaded.__setitem__(slice(None),[uuid(i) for i in range(2,4098)]) if m['method']=='thread/read' else None
        with self.scope():result=D.discover(self.p.transport)
        self.assertFalse(result.complete)
        self.assertEqual(result.reason,'discovery_incomplete')
        self.assertEqual(result.rows,())
        self.assertEqual(self.initialized(),1)
        self.assertEqual(sum(m['method']=='thread/loaded/list' for m in self.k.messages),32)
        self.assertEqual(sum(m['method']=='thread/read' for m in self.k.messages),32)

    def test_unstable_root_without_names_blocks_name_but_not_explicit_id(self):
        rows=(D.Candidate(uuid(1),'root',name='stable',names_verified=True),
              D.Candidate(uuid(2),'root',names_verified=False,stable=False))
        result=D.Discovery(rows,True,'complete','a'*64,(200,'100'))
        self.assertFalse(result.names_complete)
        with self.assertRaisesRegex(NativeFailure,'target_names_unverified'):
            result.select('stable')
        self.assertEqual(result.select('id:'+uuid(1)).thread,uuid(1))
        self.assertTrue(replace(result,rows=rows[:1]).names_complete)


if __name__=='__main__':unittest.main()

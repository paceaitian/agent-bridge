"""P5 hub 存储与 stdio 服务端（DESIGN §88.1/§88.2/§88.11，T02/T03/T15 hub 侧）：真实 SQLite 事务与管道。

覆盖：合成 ExposeAuthInfo 记录核实际公钥、错 slug/指纹/未登记/证书；fence 与旧连接停止；ledgerInstance 首次固定、
后续不符不踢健康连接；跨 source 收据拒绝；submit 幂等不延 TTL、同 op 异 hash、过期、未知目标；ACK/reject 与 L2 后拒绝；
30 秒内不重推；BLOB 分块/重算 SHA/欠块/错 offset/缺 CAS；GC 不早删被引用 blob、过期空洞 source、收据底线；
存储满无假 L1；commitCounter 每个写事务恰好加一；坏帧与超大帧；真实 `agent-bridge hub stdio` 子进程。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any

import bridge_support  # noqa: F401  导入即隔离宿主会话环境

from agentstatus_bridge.federation import codec
from agentstatus_bridge.federation.codec import CodecError
from agentstatus_bridge.federation.hub import HubSession
from agentstatus_bridge.federation.hubstore import (
    DAY_MS,
    HubStore,
    auth_fingerprint,
    openssh_fingerprint,
    parse_public_key,
)
from agentstatus_bridge.federation.transport import StreamTransport
from agentstatus_bridge.ids import new_id

T0 = 1_800_000_000_000
LEDGER_A = "1" * 32
LEDGER_B = "2" * 32
SRC = Path(__file__).resolve().parents[1] / "src"


def synthetic_key(seed: int) -> str:
    """合成专用 ed25519 公钥行（只需 wire 结构正确，不涉及真实私钥）。"""
    body = hashlib.sha256(str(seed).encode()).digest()
    blob = len(b"ssh-ed25519").to_bytes(4, "big") + b"ssh-ed25519" + (32).to_bytes(4, "big") + body
    return "ssh-ed25519 " + base64.b64encode(blob).decode() + f" test{seed}"


def fingerprint(line: str) -> str:
    return openssh_fingerprint(parse_public_key(line)[1])


def envelope(source: str, target: str, *, now: int = T0, refs: list[dict[str, Any]] | None = None,
             msg_id: str | None = None, operation_id: str | None = None, body: str = "正文") -> dict[str, Any]:
    return {"v": 1, "msg_id": msg_id or new_id(), "operationId": operation_id or new_id(), "kind": "task_state",
            "targetDeviceId": target, "authorityDeviceId": source, "taskId": "c" * 32, "attempt": None,
            "authorityRevision": 1, "relatedMessageId": None, "actor": None, "target": None,
            "senderClass": "unknown", "senderClassSource": "local-verifier", "createdAt": now,
            "expiresAt": now + 30 * DAY_MS, "title": "", "body": body, "refs": refs or [], "data": {},
            "signature": None, "encryption": None}


def blob_ref(origin: str, data: bytes) -> dict[str, Any]:
    return {"originDeviceId": origin, "originalPath": "/home/u/a.md", "resolvedPath": "/home/u/a.md", "name": "a.md",
            "transfer": "blob", "reason": None, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "hashState": "frozen"}


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> int:
        return self.now


class Client:
    """测试用最小客户端：同步请求/响应，顺序读帧。"""

    def __init__(self, transport: StreamTransport) -> None:
        self.t = transport

    def read(self, timeout: float = 5.0) -> dict[str, Any] | None:
        return self.t.read_frame(timeout=timeout)

    def handshake(self, ledger: str = LEDGER_A, capabilities: list[str] | None = None) -> dict[str, Any]:
        hello = self.read()
        assert hello is not None
        if hello["type"] != "hello":
            return hello
        self.t.write_frame({"type": "hello_ack", "protocol": {"major": 1, "minor": 0},
                            "capabilities": capabilities if capabilities is not None
                            else sorted(codec.REQUIRED_CAPABILITIES), "ledgerInstanceId": ledger})
        reply = self.read()
        assert reply is not None
        return reply

    def request(self, kind: str, **fields: Any) -> list[dict[str, Any]]:
        """发一个请求，读到对应终结帧（error/非 item 非 directory_snapshot 或 fetch_end）。"""
        rid = new_id()
        self.t.write_frame({"type": kind, "requestId": rid, **fields})
        frames: list[dict[str, Any]] = []
        while True:
            frame = self.read()
            if frame is None:
                return frames
            frames.append(frame)
            if frame.get("requestId") not in (rid, None):
                continue
            if frame["type"] in ("item",):
                continue
            if frame["type"] == "directory_snapshot" and kind == "directory_get":
                if fields.get("devices") is not None and len([f for f in frames if f["type"] == "directory_snapshot"]) \
                        < len(fields["devices"]):
                    continue
                return frames
            return frames

    def one(self, kind: str, **fields: Any) -> dict[str, Any]:
        frames = self.request(kind, **fields)
        assert frames, "connection closed"
        return frames[-1]


class HubTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.clock = Clock()
        self.free = 10 * 1024**3
        self.store, created = HubStore.init(self.root / "hub", now=T0, free_bytes=lambda _p: self.free)
        self.assertTrue(created)
        self.key_a, self.key_b, self.key_x = synthetic_key(1), synthetic_key(2), synthetic_key(3)
        self.dev_a = self.store.add_device(name="vm", fingerprint=fingerprint(self.key_a))
        self.dev_b = self.store.add_device(name="win", fingerprint=fingerprint(self.key_b))
        self.sessions: list[tuple[threading.Thread, StreamTransport]] = []

    def tearDown(self) -> None:
        for thread, client in self.sessions:
            client.close()
            thread.join(timeout=5)
        self.store.close()
        self._tmp.cleanup()

    def auth_file(self, *lines: str) -> str:
        path = self.root / f"auth-{new_id()}"
        path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
        return str(path)

    def connect(self, name: str, key: str | None, *, tick: float = 0.05) -> tuple[Client, list[int]]:
        """起一个会话线程（独立连接的 HubStore），返回客户端与退出码容器。"""
        r1, w1 = os.pipe()
        r2, w2 = os.pipe()
        server = StreamTransport(os.fdopen(r1, "rb"), os.fdopen(w2, "wb"))
        client = StreamTransport(os.fdopen(r2, "rb"), os.fdopen(w1, "wb"))
        path = self.auth_file(f"publickey {key}") if key is not None else None
        result: list[int] = []

        def serve() -> None:
            # 生产上一连接一进程；这里一连接一线程，各自打开 hub 库（sqlite 连接不跨线程）
            store = HubStore.open(self.root / "hub", free_bytes=lambda _p: self.free)
            try:
                result.append(HubSession(store, server, device_name=name, auth=lambda: auth_fingerprint(path),
                                         clock=self.clock, tick_seconds=tick, handshake_timeout=5).run())
            finally:
                store.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.sessions.append((thread, client))
        return Client(client), result

    def ready(self, name: str, key: str, ledger: str) -> Client:
        client, _ = self.connect(name, key)
        reply = client.handshake(ledger)
        self.assertEqual(reply["type"], "ready", reply)
        return client


class AuthAndFenceTests(HubTestCase):
    def test_auth_evidence_parsing(self) -> None:
        self.assertEqual(auth_fingerprint(self.auth_file(f"publickey {self.key_a}")), fingerprint(self.key_a))
        cases = {
            "missing": None,
            "none": self.auth_file("password"),
            "two": self.auth_file(f"publickey {self.key_a}", f"publickey {self.key_b}"),
            "cert": self.auth_file("publickey ssh-ed25519-cert-v01@openssh.com AAAA"),
            "garbage": self.auth_file("publickey ssh-ed25519 !!!"),
            "type_mismatch": self.auth_file("publickey ssh-rsa " + self.key_a.split()[1]),
        }
        for name, path in cases.items():
            with self.subTest(name), self.assertRaises(CodecError) as caught:
                auth_fingerprint(path)
            self.assertEqual(caught.exception.code, "auth_evidence_unavailable")

    def test_handshake_rejections_do_not_touch_fence(self) -> None:
        healthy = self.ready("vm", self.key_a, LEDGER_A)
        for name, key, ledger, code in (
                ("vm", self.key_b, LEDGER_A, "identity_mismatch"),  # B 的公钥被错绑到 vm
                ("nosuch", self.key_a, LEDGER_A, "device_unregistered"),
                ("vm", None, LEDGER_A, "auth_evidence_unavailable"),
                ("vm", self.key_a, LEDGER_B, "ledger_instance_mismatch")):
            with self.subTest(code):
                client, result = self.connect(name, key)
                reply = client.handshake(ledger)
                self.assertEqual((reply["type"], reply.get("code")), ("error", code))
        client, _ = self.connect("vm", self.key_a)
        self.assertEqual(client.handshake(LEDGER_A, capabilities=["origin-authority-v1"]).get("code"), "capability_missing")
        self.assertEqual(healthy.one("heartbeat")["type"], "heartbeat_ack")  # 失败的握手没有踢掉健康连接
        self.assertEqual(self.store.device("vm")["connection_generation"], 1)  # type: ignore[index]

    def test_new_connection_supersedes_old(self) -> None:
        old = self.ready("vm", self.key_a, LEDGER_A)
        new = self.ready("vm", self.key_a, LEDGER_A)
        reply = old.one("heartbeat")
        self.assertEqual((reply["type"], reply.get("code")), ("error", "connection_superseded"))
        self.assertIsNone(old.read())  # 旧会话随即停止
        self.assertEqual(new.one("heartbeat")["type"], "heartbeat_ack")
        self.assertEqual(self.store.device("vm")["connection_generation"], 2)  # type: ignore[index]

    def test_remove_device_stops_session_and_revokes_pending(self) -> None:
        a = self.ready("vm", self.key_a, LEDGER_A)
        b = self.ready("win", self.key_b, LEDGER_B)
        msg = envelope(self.dev_a, self.dev_b)
        self.assertEqual(a.one("submit", envelope=msg)["type"], "accepted")
        self.store.remove_device("win", now=T0 + 5)
        try:
            frame = b.read(timeout=5)
        except TimeoutError:
            self.fail("revoked session kept running")
        self.assertEqual((frame or {}).get("code"), "device_revoked")  # 一个 tick 内由周期 fence 复核发现
        self.assertIsNone(b.read())
        page = a.one("receipts_get", after=0)
        self.assertEqual([item["state"] for item in page["items"]], ["accepted", "revoked"])
        again, _ = self.connect("win", self.key_b)
        self.assertEqual(again.handshake(LEDGER_B).get("code"), "device_revoked")

    def test_receipts_constrained_to_source(self) -> None:
        a = self.ready("vm", self.key_a, LEDGER_A)
        b = self.ready("win", self.key_b, LEDGER_B)
        msg = envelope(self.dev_a, self.dev_b)
        a.one("submit", envelope=msg)
        self.assertEqual(b.one("receipts_get", after=0, sourceDeviceId=self.dev_a).get("code"), "identity_mismatch")
        page = b.one("receipts_get", msgIds=[msg["msg_id"]])
        self.assertEqual(page["byMessage"], [{"msgId": msg["msg_id"], "receipts": [], "found": False}])
        own = a.one("receipts_get", msgIds=[msg["msg_id"]])
        self.assertTrue(own["byMessage"][0]["found"])


class MailboxTests(HubTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.a = self.ready("vm", self.key_a, LEDGER_A)
        self.b = self.ready("win", self.key_b, LEDGER_B)

    def test_submit_idempotent_without_ttl_extension(self) -> None:
        msg = envelope(self.dev_a, self.dev_b)
        first = self.a.one("submit", envelope=msg)
        self.clock.now += 10_000
        again = self.a.one("submit", envelope=msg)
        self.assertEqual((first["expiresAt"], again["expiresAt"]), (first["expiresAt"], first["expiresAt"]))
        self.assertTrue(again["duplicate"])
        changed = dict(msg, body="改过")
        self.assertEqual(self.a.one("submit", envelope=changed).get("code"), "idempotency_conflict")
        reused_msg = dict(msg, operationId=new_id())
        self.assertEqual(self.a.one("submit", envelope=reused_msg).get("code"), "idempotency_conflict")
        self.assertEqual(self.a.one("submit", envelope=envelope(self.dev_a, "9" * 32)).get("code"), "destination_unknown")
        self.assertEqual(self.a.one("submit", envelope=envelope(self.dev_a, self.dev_a)).get("code"), "destination_unknown")
        stale = envelope(self.dev_a, self.dev_b, now=T0 - 31 * DAY_MS)
        stale["expiresAt"] = T0 - DAY_MS
        self.assertEqual(self.a.one("submit", envelope=stale).get("code"), "message_expired")
        future = envelope(self.dev_a, self.dev_b, now=T0 + 2 * DAY_MS)
        self.assertEqual(self.a.one("submit", envelope=future).get("code"), "frame_invalid")
        forged = dict(envelope(self.dev_a, self.dev_b), sourceDeviceId=self.dev_b)  # 自报 source 被认证映射覆盖
        self.a.one("submit", envelope=forged)
        items = [f for f in self.b.request("fetch", after=0) if f["type"] == "item"]
        self.assertEqual({item["envelope"]["sourceDeviceId"] for item in items}, {self.dev_a})
        self.assertEqual({item["sourceDeviceId"] for item in items}, {self.dev_a})

    def test_fetch_ack_reject_and_repush_window(self) -> None:
        m1, m2, m3 = (envelope(self.dev_a, self.dev_b) for _ in range(3))
        for msg in (m1, m2, m3):
            self.a.one("submit", envelope=msg)
        frames = self.b.request("fetch", after=0)
        items = [f for f in frames if f["type"] == "item"]
        self.assertEqual([i["recipientSeq"] for i in items], [1, 2, 3])
        self.assertEqual(frames[-1]["scannedThrough"], 3)
        self.assertEqual([f for f in self.b.request("fetch", after=3) if f["type"] == "item"], [])  # 30 秒内不重推
        h1, h2 = items[0]["payloadHash"], items[1]["payloadHash"]
        self.assertEqual(self.b.one("ack", msgId=m1["msg_id"], payloadHash=h1)["type"], "acked")
        self.assertEqual(self.b.one("ack", msgId=m1["msg_id"], payloadHash=h1)["type"], "acked")  # 幂等
        self.assertEqual(self.b.one("reject", msgId=m1["msg_id"], payloadHash=h1,
                                    reason="task_cancelled").get("code"), "idempotency_conflict")  # L2 后不能 reject
        self.assertEqual(self.b.one("reject", msgId=m2["msg_id"], payloadHash=h2, reason="bogus").get("code"),
                         "frame_invalid")
        self.assertEqual(self.b.one("reject", msgId=m2["msg_id"], payloadHash=h2, reason="task_cancelled").get("reason"),
                         "task_cancelled")
        self.assertEqual(self.a.one("ack", msgId=m3["msg_id"], payloadHash=items[2]["payloadHash"]).get("code"),
                         "identity_mismatch")  # 只有收件方能 ACK
        self.assertEqual(self.b.one("ack", msgId=m3["msg_id"], payloadHash="0" * 64).get("code"), "idempotency_conflict")
        self.clock.now += 31_000
        again = [f for f in self.b.request("fetch", after=3) if f["type"] == "item"]
        self.assertEqual([i["msgId"] for i in again], [m3["msg_id"]])  # 只剩未结的 m3，过 30 秒重推
        receipts = self.a.one("receipts_get", after=0)["items"]
        self.assertEqual([(r["state"], r.get("reason")) for r in receipts if r["msgId"] != m3["msg_id"]],
                         [("accepted", None), ("accepted", None), ("l2", None), ("rejected", "task_cancelled")])

    def test_fetch_batches_bounded(self) -> None:
        for _ in range(20):
            self.a.one("submit", envelope=envelope(self.dev_a, self.dev_b))
        frames = self.b.request("fetch", after=0)
        self.assertEqual(len([f for f in frames if f["type"] == "item"]), 16)
        self.assertEqual((frames[-1]["scannedThrough"], frames[-1]["more"]), (16, True))

    def test_commit_counter_one_per_write(self) -> None:
        start = self.store.read_counter()
        self.a.one("heartbeat")
        self.assertEqual(self.store.read_counter(), start + 1)
        reply = self.b.one("fetch", after=0)
        self.assertEqual(reply["commitCounter"], start + 1)  # 读不递增，回复带同快照值
        self.a.one("submit", envelope=envelope(self.dev_a, self.dev_b))
        self.assertEqual(self.store.read_counter(), start + 2)
        self.assertEqual(self.a.one("submit", envelope=envelope(self.dev_a, "9" * 32)).get("code"), "destination_unknown")
        self.assertEqual(self.store.read_counter(), start + 2)  # 回滚的事务不计数

    def test_storage_full_no_l1(self) -> None:
        self.free = 1024
        msg = envelope(self.dev_a, self.dev_b)
        self.assertEqual(self.a.one("submit", envelope=msg).get("code"), "hub_storage_full")
        self.free = 10 * 1024**3
        self.assertEqual([f for f in self.b.request("fetch", after=0) if f["type"] == "item"], [])
        self.assertEqual(self.a.one("receipts_get", after=0)["items"], [])

    def test_bad_frames(self) -> None:
        self.a.t._writer.write(b'{"type":"heartbeat","requestId":"' + b"a" * 32 + b'","x":1,"x":2}\n')  # pyright: ignore[reportPrivateUsage]
        self.a.t._writer.flush()  # pyright: ignore[reportPrivateUsage]
        self.assertEqual(self.a.read().get("code"), "frame_invalid")  # type: ignore[index]  重复键
        self.assertEqual(self.a.one("heartbeat")["type"], "heartbeat_ack")  # 坏帧后会话继续
        self.assertEqual(self.a.one("accepted").get("code"), "frame_invalid")  # 响应类帧不能当请求
        self.a.t._writer.write(b"x" * (codec.MAX_FRAME_BYTES + 10) + b"\n")  # pyright: ignore[reportPrivateUsage]
        self.a.t._writer.flush()  # pyright: ignore[reportPrivateUsage]
        self.assertEqual(self.a.read().get("code"), "frame_too_large")  # type: ignore[index]
        self.assertIsNone(self.a.read())  # 流停在行中，必须关闭

    def test_directory_put_get(self) -> None:
        snapshot = {"endpoints": [{"provider": "codex", "nativeId": "x"}], "complete": True,
                    "deviceId": self.dev_b}
        ack = self.a.one("directory_put", revision=1, snapshot=snapshot)
        self.assertEqual(ack["revision"], 1)
        self.assertEqual(self.a.one("directory_put", revision=1, snapshot={"endpoints": [{"x": "y" * 3000}],
                                                                           "complete": True}).get("code"), "frame_invalid")
        frames = self.b.request("directory_get", devices=[self.dev_a])
        (snap,) = [f for f in frames if f["type"] == "directory_snapshot"]
        self.assertEqual(snap["snapshot"]["deviceId"], self.dev_a)  # hub 覆盖自报身份
        self.assertTrue(snap["online"])
        beat = self.a.one("heartbeat")
        self.assertEqual((beat["directoryRevision"], beat["directoryDigest"]), (1, ack["digest"]))


class BlobTests(HubTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.a = self.ready("vm", self.key_a, LEDGER_A)
        self.b = self.ready("win", self.key_b, LEDGER_B)

    def upload(self, data: bytes) -> dict[str, Any]:
        sha = hashlib.sha256(data).hexdigest()
        ready = self.a.one("blob_begin", sha256=sha, size=len(data))
        if ready.get("exists"):
            return ready
        offset = 0
        while offset < len(data) or (offset == 0 and not data):
            piece = data[offset:offset + codec.BLOB_CHUNK_BYTES]
            if not piece:
                break
            ack = self.a.one("blob_chunk", uploadId=ready["uploadId"], offset=offset,
                             data=base64.b64encode(piece).decode())
            offset = ack["nextOffset"]
        return self.a.one("blob_finish", uploadId=ready["uploadId"])

    def test_multi_chunk_roundtrip_and_authorized_download(self) -> None:
        data = os.urandom(codec.BLOB_CHUNK_BYTES + 1000)
        stored = self.upload(data)
        self.assertEqual(stored["size"], len(data))
        self.assertTrue(self.a.one("blob_begin", sha256=stored["sha256"], size=len(data))["exists"])
        msg = envelope(self.dev_a, self.dev_b, refs=[blob_ref(self.dev_a, data)])
        self.assertEqual(self.a.one("submit", envelope=msg)["type"], "accepted")
        got = b""
        while True:
            part = self.b.one("blob_get", msgId=msg["msg_id"], refIndex=0, offset=len(got))
            got += base64.b64decode(part["data"])
            if part["eof"]:
                break
        self.assertEqual(got, data)
        self.assertEqual(self.a.one("blob_get", msgId=msg["msg_id"], refIndex=0, offset=0).get("code"),
                         "identity_mismatch")  # 只有收件方能取

    def test_partial_wrong_offset_hash_mismatch_and_missing(self) -> None:
        data = os.urandom(5000)
        sha = hashlib.sha256(data).hexdigest()
        ready = self.a.one("blob_begin", sha256=sha, size=len(data))
        self.assertEqual(self.a.one("blob_chunk", uploadId=ready["uploadId"], offset=10,
                                    data=base64.b64encode(data[:10]).decode()).get("code"), "attachment_offset_invalid")
        self.a.one("blob_chunk", uploadId=ready["uploadId"], offset=0, data=base64.b64encode(data[:4000]).decode())
        self.assertEqual(self.a.one("blob_finish", uploadId=ready["uploadId"]).get("code"), "attachment_offset_invalid")
        msg = envelope(self.dev_a, self.dev_b, refs=[blob_ref(self.dev_a, data)])
        self.assertEqual(self.a.one("submit", envelope=msg).get("code"), "attachment_missing")  # 残块不算 CAS
        wrong = self.a.one("blob_begin", sha256=sha, size=len(data))
        self.a.one("blob_chunk", uploadId=wrong["uploadId"], offset=0,
                   data=base64.b64encode(b"\0" * len(data)).decode())
        self.assertEqual(self.a.one("blob_finish", uploadId=wrong["uploadId"]).get("code"), "attachment_hash_mismatch")
        self.assertEqual(self.a.one("submit", envelope=msg).get("code"), "attachment_missing")
        with sqlite3.connect(self.root / "hub" / "hub.sqlite3") as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM hub_blobs").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM hub_uploads").fetchone()[0], 0)

    def test_disconnect_drops_own_upload(self) -> None:
        data = os.urandom(100)
        self.a.one("blob_begin", sha256=hashlib.sha256(data).hexdigest(), size=len(data))
        self.a.t.close()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with sqlite3.connect(self.root / "hub" / "hub.sqlite3") as conn:
                if conn.execute("SELECT COUNT(*) FROM hub_uploads").fetchone()[0] == 0:
                    break
            time.sleep(0.05)
        else:
            self.fail("upload not dropped")

    def gc(self) -> dict[str, int]:
        try:
            counts = self.store.gc(now=self.clock.now, owner="t")
        except CodecError as error:
            self.fail(f"gc failed: {error.code}")
        assert counts is not None
        return counts

    def test_gc_keeps_referenced_blob_and_reports_expired_sources(self) -> None:
        data = os.urandom(200)
        self.upload(data)
        kept = envelope(self.dev_a, self.dev_b, refs=[blob_ref(self.dev_a, data)])
        self.a.one("submit", envelope=kept)
        lapsing = envelope(self.dev_a, self.dev_b)
        lapsing["expiresAt"] = T0 + DAY_MS
        self.a.one("submit", envelope=lapsing)
        orphan = os.urandom(50)
        self.a.one("blob_begin", sha256=hashlib.sha256(orphan).hexdigest(), size=len(orphan))
        self.clock.now = T0 + 2 * DAY_MS
        counts = self.gc()
        self.assertEqual((counts["expired"], counts["blobsDeleted"], counts["uploadsDeleted"]), (1, 0, 1))
        frames = self.b.request("fetch", after=0)
        self.assertEqual([f["msgId"] for f in frames if f["type"] == "item"], [kept["msg_id"]])
        self.assertEqual(frames[-1]["expiredSources"], [self.dev_a])
        self.assertEqual(self.b.one("ack", msgId=lapsing["msg_id"],
                                    payloadHash=codec.payload_hash(lapsing)).get("code"), "message_expired")
        item = next(f for f in frames if f["type"] == "item")
        self.b.one("ack", msgId=kept["msg_id"], payloadHash=item["payloadHash"])
        self.clock.now += 31 * DAY_MS
        counts = self.gc()
        self.assertEqual(counts["contentCleared"], 2)
        counts = self.gc()
        self.assertEqual(counts["blobsDeleted"], 0)  # 引用刚删的这一轮之前已无引用：上一轮已删
        with sqlite3.connect(self.root / "hub" / "hub.sqlite3") as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM hub_blobs").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM hub_messages").fetchone()[0], 2)  # 去重行保留
        self.clock.now += 30 * DAY_MS
        self.gc()
        self.assertEqual(self.a.one("receipts_get", after=0).get("code"), "cursor_gap")
        self.assertTrue(self.b.request("fetch", after=0)[-1]["gap"])

    def test_gc_lease(self) -> None:
        self.assertIsNotNone(self.store.gc(now=T0, owner="x"))
        self.assertIsNone(self.store.gc(now=T0 + 1, owner="y"))
        self.assertIsNotNone(self.store.gc(now=T0 + 200_000, owner="y"))


class SchemaTests(HubTestCase):
    def test_ddl_constraints(self) -> None:
        with sqlite3.connect(self.root / "hub" / "hub.sqlite3") as conn:
            row = ("m" * 32, self.dev_a, "o" * 32, self.dev_b, 1, "h" * 64, "{}", 2, T0, T0 + 1, "queued")
            conn.execute("INSERT INTO hub_messages(msg_id,source_device,operation_id,target_device,recipient_seq,"
                         "payload_hash,envelope_json,payload_bytes,accepted_at,expires_at,outcome)"
                         " VALUES (?,?,?,?,?,?,?,?,?,?,?)", row)
            for changed in ((("n" * 32,) + row[1:]),  # 同 (source, operation)
                            (("n" * 32, self.dev_a, "p" * 32) + row[3:])):  # 同 (target, seq)
                with self.assertRaises(sqlite3.IntegrityError):
                    conn.execute("INSERT INTO hub_messages(msg_id,source_device,operation_id,target_device,"
                                 "recipient_seq,payload_hash,envelope_json,payload_bytes,accepted_at,expires_at,"
                                 "outcome) VALUES (?,?,?,?,?,?,?,?,?,?,?)", changed)
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("INSERT INTO hub_blobs(sha256,size,data,verified_at) VALUES ('x',8388609,x'00',0)")

    def test_init_existing_keeps_hub_id(self) -> None:
        hub_id = self.store.hub_id()
        again, created = HubStore.init(self.root / "hub", now=T0 + 1)
        self.assertFalse(created)
        self.assertEqual(again.hub_id(), hub_id)
        again.close()
        self.assertEqual(oct((self.root / "hub").stat().st_mode & 0o777), "0o700")
        self.assertEqual(oct((self.root / "hub" / "hub.sqlite3").stat().st_mode & 0o777), "0o600")


class StdioProcessTests(HubTestCase):
    def test_real_stdio_entry(self) -> None:
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(self.root), "LANG": "C.UTF-8",
               "PYTHONPATH": str(SRC), "SSH_USER_AUTH": self.auth_file(f"publickey {self.key_a}"),
               "SSH_ORIGINAL_COMMAND": "rm -rf /"}  # 入口不解释原始命令
        proc = subprocess.Popen([sys.executable, "-P", "-m", "agentstatus_bridge", "hub", "--state-dir",
                                 str(self.root / "hub"), "stdio", "--device", "vm"],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                                cwd=str(self.root))
        assert proc.stdin is not None and proc.stdout is not None
        client = Client(StreamTransport(proc.stdout, proc.stdin))
        try:
            hello = client.read(timeout=20)
            assert hello is not None
            self.assertEqual((hello["type"], hello["deviceId"], hello["hubId"]),
                             ("hello", self.dev_a, self.store.hub_id()))
            client.t.write_frame({"type": "hello_ack", "protocol": {"major": 1, "minor": 0},
                                  "capabilities": sorted(codec.REQUIRED_CAPABILITIES), "ledgerInstanceId": LEDGER_A})
            self.assertEqual(client.read(timeout=20)["type"], "ready")  # type: ignore[index]
            self.assertEqual(client.one("heartbeat")["type"], "heartbeat_ack")
        finally:
            client.t.close()
            proc.wait(timeout=20)
        self.assertEqual(proc.returncode, 0)
        assert proc.stderr is not None
        self.assertEqual(proc.stderr.read(), b"")
        proc.stderr.close()

    def test_add_device_prints_forced_command(self) -> None:
        key_file = self.root / "relay.pub"
        key_file.write_text(self.key_x + "\n", encoding="utf-8")
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(self.root), "PYTHONPATH": str(SRC)}
        out = subprocess.run([sys.executable, "-P", "-m", "agentstatus_bridge", "hub", "--state-dir",
                              str(self.root / "hub"), "add-device", "--name", "wsl", "--public-key-file",
                              str(key_file), "--command-path", "/opt/ab/bin/agent-bridge"],
                             capture_output=True, text=True, env=env, cwd=str(self.root), timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        info, line = out.stdout.strip().splitlines()
        self.assertEqual(json.loads(info)["fingerprint"], fingerprint(self.key_x))
        self.assertTrue(line.startswith('restrict,command="/opt/ab/bin/agent-bridge hub --state-dir '))
        self.assertIn(" stdio --device wsl\" ssh-ed25519 ", line)
        dup = subprocess.run([sys.executable, "-P", "-m", "agentstatus_bridge", "hub", "--state-dir",
                              str(self.root / "hub"), "add-device", "--name", "other", "--public-key-file",
                              str(key_file)], capture_output=True, text=True, env=env, cwd=str(self.root), timeout=30)
        self.assertEqual((dup.returncode, dup.stderr.strip()), (3, "public_key_taken"))


if __name__ == "__main__":
    unittest.main()

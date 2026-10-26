"""P5 联邦编码（DESIGN §88.2/§88.3，T01）：有界帧、严格 JSON、规范化哈希、信封与 checkpoint 形状。"""

from __future__ import annotations

import io
import unittest

import bridge_support  # noqa: F401  导入即隔离宿主会话环境

from agentstatus_bridge.federation import codec
from agentstatus_bridge.federation.codec import CodecError
from agentstatus_bridge.federation.refs import (
    AttemptDefinition,
    Checkpoint,
    RemoteEndpointRef,
    TargetRef,
    WireActor,
)
from agentstatus_bridge.model import EndpointRef, Provider

A = "a" * 32
B = "b" * 32
TASK = "c" * 32


def remote(device: str = B, endpoint: str = "e" * 32, native: str = "11111111-2222") -> RemoteEndpointRef:
    return RemoteEndpointRef(device_id=device, provider=Provider.CLAUDE, native_id=native, endpoint_id=endpoint)


def checkpoint(**changes: object) -> Checkpoint:
    data: dict[str, object] = {
        "authority_device": A,
        "task_id": TASK,
        "revision": 1,
        "title": "任务",
        "flow": "handoff",
        "control": "active",
        "max_seq": 1,
        "current_work_seq": 1,
        "attempts": (AttemptDefinition(seq=1, msg_id="d" * 32, role="handoff", target=remote()),),
        "members": (A, B),
        "origin": WireActor(device_id=A, provider=Provider.CODEX, native_id="019a-x", wire_token="codex@019a"),
    }
    data.update(changes)
    return Checkpoint(**data)  # pyright: ignore[reportArgumentType]


def envelope(**changes: object) -> dict[str, object]:
    data: dict[str, object] = {
        "v": 1,
        "msg_id": "d" * 32,
        "operationId": "f" * 32,
        "kind": "handoff",
        "targetDeviceId": B,
        "authorityDeviceId": A,
        "taskId": TASK,
        "attempt": 1,
        "authorityRevision": 1,
        "relatedMessageId": None,
        "senderClass": "unknown",
        "senderClassSource": "local-verifier",
        "createdAt": 1,
        "expiresAt": 2,
        "title": "任务",
        "body": "正文",
        "refs": [],
        "data": {"checkpoint": checkpoint().to_dict()},
        "signature": None,
        "encryption": None,
    }
    data.update(changes)
    return data


class FrameTests(unittest.TestCase):
    def test_round_trip_and_canonical(self) -> None:
        stream = io.BytesIO()
        codec.write_frame(stream, {"type": "heartbeat", "b": 2, "a": "中"})
        self.assertEqual(b'{"a":"\xe4\xb8\xad","b":2,"type":"heartbeat"}\n', stream.getvalue())
        stream.seek(0)
        self.assertEqual({"type": "heartbeat", "a": "中", "b": 2}, codec.read_frame(stream))
        self.assertIsNone(codec.read_frame(stream))

    def test_newline_in_text_is_escaped(self) -> None:
        stream = io.BytesIO()
        codec.write_frame(stream, {"type": "heartbeat", "note": "一\n二"})
        self.assertEqual(1, stream.getvalue().count(b"\n"))
        stream.seek(0)
        self.assertEqual("一\n二", (codec.read_frame(stream) or {})["note"])

    def test_sticky_frames(self) -> None:
        stream = io.BytesIO(b'{"type":"heartbeat"}\n{"type":"heartbeat_ack"}\n')
        self.assertEqual("heartbeat", (codec.read_frame(stream) or {})["type"])
        self.assertEqual("heartbeat_ack", (codec.read_frame(stream) or {})["type"])

    def test_frame_size_boundary(self) -> None:
        overhead = len(b'{"pad":"","type":"heartbeat"}')
        exact = b'{"pad":"' + b"x" * (codec.MAX_FRAME_BYTES - overhead) + b'","type":"heartbeat"}'
        self.assertEqual(codec.MAX_FRAME_BYTES, len(exact))
        self.assertEqual("heartbeat", (codec.read_frame(io.BytesIO(exact + b"\n")) or {})["type"])
        over = b'{"pad":"' + b"x" * (codec.MAX_FRAME_BYTES - overhead + 1) + b'","type":"heartbeat"}'
        with self.assertRaises(CodecError) as caught:
            codec.read_frame(io.BytesIO(over + b"\n"))
        self.assertEqual("frame_too_large", caught.exception.code)
        with self.assertRaises(CodecError) as caught:
            codec.encode_frame({"type": "heartbeat", "pad": "x" * codec.MAX_FRAME_BYTES})
        self.assertEqual("frame_too_large", caught.exception.code)

    def test_truncated_and_bad_input(self) -> None:
        cases = {
            b'{"type":"heartbeat"}': "truncated",
            b'{"type":"heartbeat","type":"x"}\n': "duplicate_key",
            b'{"type":"heartbeat","n":NaN}\n': "non_finite_number",
            b'{"type":"heartbeat","n":Infinity}\n': "non_finite_number",
            b'["type"]\n': "not_object",
            b'\xff\n': "utf8",
            b'{"type":"nope"}\n': "unknown_type",
            b'{"type":"heartbeat","requestId":"XYZ"}\n': "request_id",
        }
        for raw, detail in cases.items():
            with self.subTest(raw=raw):
                with self.assertRaises(CodecError) as caught:
                    codec.read_frame(io.BytesIO(raw))
                self.assertEqual("frame_invalid", caught.exception.code)
                self.assertEqual(detail, caught.exception.detail)

    def test_depth_limit(self) -> None:
        def nested(depth: int) -> bytes:
            inner = b"1"
            for _ in range(depth - 1):
                inner = b'{"x":' + inner + b"}"
            return b'{"type":"heartbeat","x":' + inner + b"}"

        # 顶层 object 算第 1 层：x 下面再套 14 层 object 共 16 层
        self.assertIsNotNone(codec.decode_frame(nested(16)))
        with self.assertRaises(CodecError):
            codec.decode_frame(nested(17))

    def test_error_frame_is_closed(self) -> None:
        self.assertEqual({"type": "error", "code": "hub_busy", "retryable": True}, codec.error_frame("hub_busy"))
        self.assertFalse(codec.error_frame("identity_mismatch")["retryable"])
        with self.assertRaises(ValueError):
            codec.error_frame("made_up")

    def test_bool_is_not_count(self) -> None:
        self.assertFalse(codec.is_count(True))
        self.assertTrue(codec.is_count(0))
        self.assertFalse(codec.is_positive(0))
        self.assertFalse(codec.is_count(2**63))


class EnvelopeTests(unittest.TestCase):
    def test_valid_envelope(self) -> None:
        codec.check_envelope(envelope())

    def test_payload_hash_ignores_hub_stamps_keeps_unknown(self) -> None:
        base = envelope()
        stamped = dict(base, sourceDeviceId=A, acceptedAt=9, recipientSeq=3)
        self.assertEqual(codec.payload_hash(base), codec.payload_hash(stamped))
        self.assertNotEqual(codec.payload_hash(base), codec.payload_hash(dict(base, futureField=1)))
        self.assertNotEqual(codec.payload_hash(base), codec.payload_hash(dict(base, body="改")))

    def test_free_text_limit_counts_note(self) -> None:
        cp = checkpoint().to_dict()
        half = "x" * (codec.MAX_FREE_TEXT_BYTES // 2)
        codec.check_envelope(envelope(body=half, data={"checkpoint": cp, "note": half}))
        with self.assertRaises(CodecError):
            codec.check_envelope(envelope(body=half, data={"checkpoint": cp, "note": half + "y"}))

    def test_attempt_kind_requires_checkpoint(self) -> None:
        with self.assertRaises(CodecError) as caught:
            codec.check_envelope(envelope(data={}))
        self.assertEqual("checkpoint_required", caught.exception.detail)
        codec.check_envelope(envelope(kind="report", data={}))

    def test_signature_must_be_null(self) -> None:
        with self.assertRaises(CodecError) as caught:
            codec.check_envelope(envelope(signature="sig"))
        self.assertEqual("capability_missing", caught.exception.code)

    def test_bad_fields(self) -> None:
        for key, value in (("msg_id", "D" * 32), ("kind", "exec"), ("senderClass", "admin"), ("attempt", 65),
                           ("authorityRevision", 0), ("createdAt", True), ("title", "x" * 121), ("v", 2)):
            with self.subTest(key=key):
                with self.assertRaises(CodecError):
                    codec.check_envelope(envelope(**{key: value}))

    def test_refs(self) -> None:
        blob = {"originDeviceId": A, "originalPath": "/home/u/link.md", "resolvedPath": "/mnt/x.md", "name": "x.md",
                "transfer": "blob", "reason": None, "size": codec.MAX_BLOB_BYTES, "sha256": "0" * 64, "hashState": "frozen"}
        reference = dict(blob, transfer="reference", reason="single_file_limit", size=codec.MAX_BLOB_BYTES + 1,
                         sha256=None, hashState="not_computed_size_limit")
        codec.check_refs([blob, reference])
        with self.assertRaises(CodecError) as caught:
            codec.check_refs([dict(blob, size=codec.MAX_BLOB_BYTES + 1)])
        self.assertEqual("attachment_too_large", caught.exception.code)
        with self.assertRaises(CodecError):
            codec.check_refs([blob] * 5)  # 5×8MiB 超过 32MiB
        with self.assertRaises(CodecError):
            codec.check_refs([reference] * 17)
        with self.assertRaises(CodecError):
            codec.check_refs([dict(blob, name="../x")])
        with self.assertRaises(CodecError):
            codec.check_refs([dict(reference, sha256="0" * 64)])

    def test_envelope_size_limit(self) -> None:
        refs = [{"originDeviceId": A, "originalPath": "/" + "p" * 4000, "resolvedPath": "/" + "q" * 4000,
                 "name": f"n{i}", "transfer": "reference", "reason": "single_file_limit", "size": 1,
                 "sha256": None, "hashState": "not_computed_size_limit"} for i in range(16)]
        big = envelope(refs=refs, data={"checkpoint": checkpoint().to_dict(), "pad": "z" * 400_000})
        with self.assertRaises(CodecError) as caught:
            codec.check_envelope(big)
        self.assertEqual("envelope_too_large", caught.exception.detail)


class RefTests(unittest.TestCase):
    def test_remote_identity_includes_device(self) -> None:
        self.assertTrue(remote().same_endpoint(remote()))
        self.assertFalse(remote().same_endpoint(remote(device=A)))
        self.assertFalse(remote().same_endpoint(remote(endpoint="9" * 32)))
        labelled = RemoteEndpointRef(device_id=B, provider=Provider.CLAUDE, native_id="11111111-2222",
                                     endpoint_id="e" * 32, display_label="别名")
        self.assertTrue(remote().same_endpoint(labelled))

    def test_remote_round_trip_and_reject(self) -> None:
        item = RemoteEndpointRef(device_id=B, provider=Provider.CODEX, native_id="019a", endpoint_id="e" * 32,
                                 endpoint_revision=3, capabilities=("inbox",))
        self.assertEqual(item, RemoteEndpointRef.from_dict(item.to_dict()))
        for bad in ({"nativeId": "-"}, {"deviceId": "x"}, {"provider": "gpt"}, {"endpointRevision": 0}):
            with self.subTest(bad=bad):
                with self.assertRaises(CodecError):
                    RemoteEndpointRef.from_dict(dict(item.to_dict(), **bad))

    def test_target_union(self) -> None:
        local = EndpointRef(provider=Provider.CLAUDE, native_id="11111111-2222", pid=10, start_ticks="99")
        both = TargetRef(remote=remote(), local=local)
        self.assertEqual(both, TargetRef.from_dict(both.to_dict()))
        only = TargetRef(remote=remote())
        self.assertFalse(TargetRef.from_dict(only.to_dict()).is_local)
        mismatch = dict(both.to_dict(), local=dict(local.to_dict(), nativeId="other"))
        with self.assertRaises(CodecError):
            TargetRef.from_dict(mismatch)
        with self.assertRaises(CodecError):
            TargetRef.from_dict(dict(both.to_dict(), local={"provider": "claude"}))

    def test_checkpoint_round_trip(self) -> None:
        item = checkpoint(verdict="approved", accepted_at=5)
        self.assertEqual(item, Checkpoint.from_dict(item.to_dict()))
        self.assertTrue(item.finished)
        self.assertEqual(1, (item.attempt(1) or AttemptDefinition(0, "", "", remote())).seq)

    def test_checkpoint_rejects(self) -> None:
        good = checkpoint().to_dict()
        for bad in ({"revision": 0}, {"control": "running"}, {"maxSeq": 65}, {"members": ["x"]},
                    {"attempts": [good["attempts"][0], good["attempts"][0]]}, {"maxSeq": 0}):
            with self.subTest(bad=bad):
                with self.assertRaises(CodecError):
                    Checkpoint.from_dict(dict(good, **bad))
        with self.assertRaises(CodecError):
            Checkpoint.from_dict(dict(good, title="t" * 121))

    def test_checkpoint_size_bound(self) -> None:
        many = tuple(AttemptDefinition(seq=i, msg_id=f"{i:032x}", role="handoff",
                                       target=remote(native="n" * 128)) for i in range(1, 65))
        item = checkpoint(attempts=many, max_seq=64)
        self.assertLess(len(codec.canonical_bytes(item.to_dict())), codec.MAX_CHECKPOINT_BYTES)


if __name__ == "__main__":
    unittest.main()

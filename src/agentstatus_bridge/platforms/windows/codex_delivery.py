"""Windows Codex add only. Uses the common codec, never a CLI fallback.

任务内补充消息（context.steer，DESIGN §95.5.4）：同一条连接上先只读 thread/read 与 thread/turns/list，有进行中的一轮才
turn/steer；steer 被已知文案确定拒绝时复位写入闩锁、退回 thread/queue/add；steer 帧开始发送后的其余问题记 UNKNOWN。
只读步骤出现非超时失败（读到一半失步、收到服务端请求、应答 id 不符）或请求帧发送失败（含发送超时：帧可能只写出
一半）时还没写过任何投递帧：关掉这条连接，新开一条直接走 thread/queue/add（G4 审计 r1 P3-3/F-6、r1 复核 Opus P3-1），
不记 FAILED。
"""
from dataclasses import replace
from contextlib import ExitStack
import time
from collections.abc import Callable

from ...model import Delivery, Endpoint, Provider
from ...transports import DeliveryContext, DeliveryOutcome
from ...transports.codex_native import BoundedConnection, NativeFailure, native_id, project_thread
from ...transports.codex_rpc import (
    STEER_PATH_NO_ACTIVE_TURN,
    STEER_PATH_REJECTED,
    STEER_PATH_STEERED,
    STEER_PATH_THREAD_NOT_ACTIVE,
    STEER_PATH_THREAD_UNREADABLE,
    STEER_PATH_TURNS_UNREADABLE,
    STEER_PATH_UNKNOWN,
    classify_error,
    classify_steer_error,
    in_progress_turn,
    interpret_steer_success,
    interpret_success,
    steer_error_reason,
    steer_request,
    thread_active,
    thread_read_request,
    turns_list_request,
)
from ...transports.websocket import MAX_MESSAGE_BYTES, _Closed, _Timeout
from ..factory import get_platform
from .codex_discovery import Reader
from .codex_sql import read_classes
from .local_transport import WindowsPlatform

TOTAL_SECONDS = 600.0
# 写前失败的诊断阶段（DESIGN §103.1 第 0 步结论）：只进本机 detail 的 preSendStage，不上线、内容无关
PRE_SEND_STAGES = frozenset({'connect', 'handshake', 'initialize', 'loaded', 'sql', 'read', 'boundary'})
# 补充消息两步只读各自的截止时间（仍受总预算约束）；turns/list 每次重放整份 rollout，给得宽一些
READ_STEP_SECONDS = 15.0
TURNS_STEP_SECONDS = 30.0


def pre_send_diagnostic(stage: str, error: BaseException) -> dict[str, object]:
    """写前失败的本机诊断：阶段（闭集）、异常类别名、直接起因的类别名与 winerror 数值；不含消息文本与路径。

    winerror 取异常本身或直接起因上的整数属性（`_Timeout` 由底层 TimeoutError 链出时看起因），用来分辨真截止与
    其他系统错误；这些键只留在投递设备本机（跨设备只同步 steer 闭集，见 federation/views.steer_detail）。
    """
    detail: dict[str, object] = {'preSendStage': stage if stage in PRE_SEND_STAGES else 'connect',
                                 'preSendError': type(error).__name__}
    cause = error.__cause__ or error.__context__
    if cause is not None:
        detail['preSendCause'] = type(cause).__name__
    for item in (error, cause):
        winerror = getattr(item, 'winerror', None)
        if type(winerror) is int:
            detail['preSendWinerror'] = winerror
            break
    return detail


class _ReadStepFailed(Exception):
    """补充消息的只读步骤非超时失败：连接不再可用，但还没写过任何投递帧。"""

    def __init__(self, reason: str, step_path: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.step_path = step_path


class CodexTransport:
    provider = Provider.CODEX

    def deliver(self, endpoint: Endpoint, text: str, context: DeliveryContext) -> DeliveryOutcome:
        return self._deliver(endpoint, text, context)

    def _deliver(self, endpoint: Endpoint, text: str, context: DeliveryContext, *, deadline: float | None = None,
                 read_failed: tuple[str, str] | None = None) -> DeliveryOutcome:
        """一次投递；read_failed=(原因, 所在步骤的 steerPath) 表示上一条连接的只读步骤已失败、这是新开的队列连接。"""
        backend = get_platform().transport
        if not isinstance(backend, WindowsPlatform) or endpoint.ref.provider is not Provider.CODEX:
            return DeliveryOutcome(Delivery.FAILED, 'windows_provider_not_enabled')
        clock, started = time.monotonic, False
        # steering：已开始发送的是 steer 帧（结果不明时的原因码与证据随之不同）
        steering = False
        steer_path: str | None = read_failed[1] if read_failed is not None else None
        steer_rejected: str | None = None
        deadline = clock() + TOTAL_SECONDS if deadline is None else deadline
        fallback: tuple[str, str] | None = None
        client = None
        version = 'unknown'
        root = None
        # 当前所在的写前阶段（诊断用，见 pre_send_diagnostic）
        stage = 'connect'

        def at(name: str) -> None:
            nonlocal stage
            stage = name

        def steer_detail(path: str) -> dict[str, object]:
            # steered / steer_unknown 不是队列样本：不写 queueChannel/queueOutput（doctor 不计入）
            assert client is not None
            return {'steerPath': path, 'codexVersion': version, 'serverVersion': client.server_version}

        try:
            version = backend.codex_cli_version() or 'unknown'
            if clock() >= deadline:
                raise NativeFailure('codex_deadline_before_send')
            with backend.codex_add_scope(version), ExitStack() as leases:
                files = backend.files
                home, sql_root = files.codex_home(), files.codex_sqlite_home()
                leases.enter_context(files.external_directory(home))
                leases.enter_context(files.external_directory(sql_root or home))
                root = files.root_identity(home, sql_root)
                if root is None or root != endpoint.ref.data_root:
                    raise NativeFailure('target_root_changed')
                client = BoundedConnection(home, deadline, clock, stage=at)
                at('initialize')
                expected = endpoint.ref.pid, endpoint.ref.start_ticks

                def unchanged() -> None:
                    assert client is not None
                    pid, birth = backend.read_identity(client._socket)
                    if (pid, 'win-filetime:'+birth) != expected:
                        raise NativeFailure('target_generation_changed')
                    if files.root_identity(home, sql_root) != root:
                        raise NativeFailure('target_root_changed')
                    client.unchanged()

                unchanged()
                client.initialize(version, deadline, experimental=True)
                reader = Reader(client, deadline)
                thread = endpoint.ref.native_id
                at('loaded')
                if native_id(thread) != thread or thread not in reader.loaded():
                    raise NativeFailure('target_not_loaded')
                at('sql')
                records = read_classes(files, sql_root or home, [thread], deadline, clock)
                fact = records.get(thread)
                classified: object | None = None  # 分类时已读过的 metadata-only thread/read：补充消息复用它的 status
                if fact is None:
                    at('read')
                    result = classified = reader.request('thread/read', {'threadId': thread, 'includeTurns': False})
                    fact = project_thread(result.get('thread') if isinstance(result, dict) else None, thread)
                if fact.kind != 'root':
                    raise NativeFailure('target_not_root')
                at('loaded')
                if thread not in reader.loaded():
                    raise NativeFailure('target_not_loaded')
                request_id = reader.request_id
                stale: list[int] = []

                def boundary() -> None:
                    nonlocal started
                    assert client is not None
                    unchanged()
                    client._remaining(deadline)
                    try:
                        if context.before_send is not None:
                            context.before_send()
                    except Exception as error:
                        raise NativeFailure('boundary_store_busy' if getattr(error, 'code', None) == 'store_busy'
                                            else 'boundary_record_failed') from error
                    client._remaining(deadline)
                    unchanged()
                    started = True  # next operation may write a partial add/steer frame

                def read(build: Callable[[int, str], dict[str, object]], seconds: float, path: str) -> object | None:
                    """补充消息的一步只读：结果或 None（错误响应、在消息边界上的超时）。

                    失步、收到服务端请求、应答 id 不符等非超时失败，以及请求帧没发完（发送超时也算：帧可能只写出
                    一半，流已不在消息边界上，与 Linux `_read` 同口径）：这条连接不能再用，但还没写过投递帧——
                    抛 _ReadStepFailed，由外层新开连接走队列。总预算用完照旧按超时失败。
                    """
                    nonlocal request_id
                    assert client is not None
                    request_id += 1
                    step = min(deadline, clock() + seconds)
                    try:
                        client._send_json(build(request_id, thread), step)
                    except (_Timeout, TimeoutError, _Closed, NativeFailure, OSError, ValueError) as failure:
                        if clock() >= deadline:
                            raise
                        raise _ReadStepFailed('codex_steer_read_desync', path) from failure
                    try:
                        response = client.response(request_id, step, stale=stale)
                    except (_Timeout, TimeoutError):
                        if clock() >= deadline:
                            raise
                        if client.desynced:
                            raise _ReadStepFailed('codex_steer_read_desync', path) from None
                        stale.append(request_id)  # 迟到的应答在后面的等待里按 id 丢弃
                        return None
                    except NativeFailure as failure:
                        raise _ReadStepFailed(failure.reason, path) from failure
                    except OSError as failure:
                        raise _ReadStepFailed('codex_transport_error', path) from failure
                    return response.get('result') if 'result' in response else None

                def send(payload: bytes) -> None:
                    assert client is not None
                    if len(payload) > MAX_MESSAGE_BYTES or (client._max_unfragmented is not None
                                                          and len(payload) > client._max_unfragmented):
                        raise NativeFailure('provider_payload_too_large')
                    client.on_write_start = boundary
                    try:
                        client._send_frame(1, payload, deadline)
                    finally:
                        client.on_write_start = None

                if context.steer:
                    at('read')
                    active = thread_active(classified if classified is not None
                                           else read(thread_read_request, READ_STEP_SECONDS,
                                                     STEER_PATH_THREAD_UNREADABLE))
                    recognized, turn = (in_progress_turn(read(turns_list_request, TURNS_STEP_SECONDS,
                                                              STEER_PATH_TURNS_UNREADABLE))
                                        if active is True else (False, None))
                    if active is not True:
                        steer_path = STEER_PATH_THREAD_NOT_ACTIVE if active is False else STEER_PATH_THREAD_UNREADABLE
                    elif turn is None:
                        steer_path = STEER_PATH_NO_ACTIVE_TURN if recognized else STEER_PATH_TURNS_UNREADABLE
                    else:
                        request_id += 1
                        steer_id = request_id
                        steering = True
                        at('boundary')
                        send(client._encode(steer_request(steer_id, thread, text, context.message_uuid, turn)))
                        response = client.response(steer_id, deadline, stale=stale)
                        unchanged()
                        if 'error' not in response:
                            if interpret_steer_success(response.get('result')):
                                return DeliveryOutcome(Delivery.DELIVERED, 'codex_steered', None,
                                                       steer_detail(STEER_PATH_STEERED))
                            return DeliveryOutcome(Delivery.UNKNOWN, 'codex_steer_unparsed_output', None,
                                                   steer_detail(STEER_PATH_UNKNOWN))
                        rejected = classify_steer_error(response['error'])
                        if rejected is None:
                            return DeliveryOutcome(Delivery.UNKNOWN, steer_error_reason(response['error']), None,
                                                   steer_detail(STEER_PATH_UNKNOWN))
                        # 确定未送入：复位写入闩锁，同一次投递退回队列（add 前仍过一次 boundary）
                        started = steering = False
                        steer_path, steer_rejected = STEER_PATH_REJECTED, rejected
                request_id += 1
                add_id = request_id
                at('boundary')
                send(client._encode({'id': add_id, 'method': 'thread/queue/add', 'params': {
                    'threadId': thread, 'input': [{'type': 'text', 'text': text, 'text_elements': []}],
                    'clientUserMessageId': context.message_uuid}}))
                response = client.response(add_id, deadline, stale=stale)
                unchanged()
                if 'error' in response:
                    delivery, reason, output = classify_error(response['error'])
                    item = None
                else:
                    delivery, reason, item, output = interpret_success(response.get('result'), context.message_uuid)
                detail: dict[str, object] = {'queueChannel': 'rpc', 'codexVersion': version,
                                             'serverVersion': client.server_version, 'queueOutput': output}
                if steer_path is not None:
                    detail['steerPath'] = steer_path
                if steer_rejected is not None:
                    detail['steerRejected'] = steer_rejected
                if read_failed is not None:
                    detail['steerReadFailed'] = read_failed[0]
                return DeliveryOutcome(delivery, reason, item, detail, root if delivery is Delivery.QUEUED else None)
        except _ReadStepFailed as failure:
            # 只读步骤在任何投递帧之前：started 必为 False。连接已不可用，下面新开一条走队列
            fallback = (failure.reason, failure.step_path)
        except Exception as error:
            timeout = isinstance(error, (_Timeout, TimeoutError))
            if started and steering:
                return DeliveryOutcome(Delivery.UNKNOWN, 'codex_steer_timeout' if timeout else 'codex_transport_error',
                                       detail=steer_detail(STEER_PATH_UNKNOWN))
            if started:
                reason = 'codex_queue_timeout' if timeout else 'codex_transport_error'
            elif isinstance(error, NativeFailure):
                reason = error.reason
            elif timeout:
                reason = 'codex_deadline_before_send'
            else:
                reason = 'codex_preflight_failed'
            detail = {'queueChannel': 'rpc', 'codexVersion': version,
                      'serverVersion': client.server_version if client else 'unknown'}
            if steer_path is not None:
                detail['steerPath'] = steer_path
            if read_failed is not None:
                detail['steerReadFailed'] = read_failed[0]
            if not started:
                detail.update(pre_send_diagnostic(stage, error))
            return DeliveryOutcome(Delivery.UNKNOWN if started else Delivery.FAILED, reason, detail=detail)
        finally:
            if client is not None:
                client.close()
        # 新开的连接不再走 steer：只读结果已不可信，按队列投递（add 前照样过 boundary）；同一总预算
        return self._deliver(endpoint, text, replace(context, steer=False), deadline=deadline, read_failed=fallback)

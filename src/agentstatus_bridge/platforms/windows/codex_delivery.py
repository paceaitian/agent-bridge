"""Windows Codex add only. Uses the common codec, never a CLI fallback."""
from contextlib import ExitStack
import time

from ...model import Delivery, Endpoint, Provider
from ...transports import DeliveryContext, DeliveryOutcome
from ...transports.codex_native import BoundedConnection, NativeFailure, native_id, project_thread
from ...transports.codex_rpc import classify_error, interpret_success
from ...transports.websocket import MAX_MESSAGE_BYTES, _Timeout
from ..factory import get_platform
from .codex_discovery import Reader
from .codex_sql import read_classes
from .local_transport import WindowsPlatform

TOTAL_SECONDS = 600.0


class CodexTransport:
    provider = Provider.CODEX

    def deliver(self, endpoint: Endpoint, text: str, context: DeliveryContext) -> DeliveryOutcome:
        backend = get_platform().transport
        if not isinstance(backend, WindowsPlatform) or endpoint.ref.provider is not Provider.CODEX:
            return DeliveryOutcome(Delivery.FAILED, 'windows_provider_not_enabled')
        clock, started = time.monotonic, False
        deadline = clock() + TOTAL_SECONDS
        client = None
        version = 'unknown'
        root = None
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
                client = BoundedConnection(home, deadline, clock)
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
                if native_id(thread) != thread or thread not in reader.loaded():
                    raise NativeFailure('target_not_loaded')
                records = read_classes(files, sql_root or home, [thread], deadline, clock)
                fact = records.get(thread)
                if fact is None:
                    result = reader.request('thread/read', {'threadId': thread, 'includeTurns': False})
                    fact = project_thread(result.get('thread') if isinstance(result, dict) else None, thread)
                if fact.kind != 'root':
                    raise NativeFailure('target_not_root')
                if thread not in reader.loaded():
                    raise NativeFailure('target_not_loaded')
                request_id = reader.request_id+1
                payload = client._encode({'id': request_id, 'method': 'thread/queue/add', 'params': {
                    'threadId': thread, 'input': [{'type': 'text', 'text': text, 'text_elements': []}],
                    'clientUserMessageId': context.message_uuid}})
                if len(payload) > MAX_MESSAGE_BYTES or (client._max_unfragmented is not None
                                                      and len(payload) > client._max_unfragmented):
                    raise NativeFailure('provider_payload_too_large')

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
                    started = True  # next operation may write a partial add frame

                client.on_write_start = boundary
                try:
                    client._send_frame(1, payload, deadline)
                finally:
                    client.on_write_start = None
                response = client.response(request_id, deadline)
                unchanged()
                if 'error' in response:
                    delivery, reason, output = classify_error(response['error'])
                    item = None
                else:
                    delivery, reason, item, output = interpret_success(response.get('result'), context.message_uuid)
                return DeliveryOutcome(delivery, reason, item,
                                       {'queueChannel': 'rpc', 'codexVersion': version,
                                        'serverVersion': client.server_version, 'queueOutput': output},
                                       root if delivery is Delivery.QUEUED else None)
        except Exception as error:
            if started:
                reason = 'codex_queue_timeout' if isinstance(error, (_Timeout, TimeoutError)) else 'codex_transport_error'
            elif isinstance(error, NativeFailure):
                reason = error.reason
            elif isinstance(error, (_Timeout, TimeoutError)):
                reason = 'codex_deadline_before_send'
            else:
                reason = 'codex_preflight_failed'
            return DeliveryOutcome(Delivery.UNKNOWN if started else Delivery.FAILED, reason,
                                   detail={'queueChannel': 'rpc', 'codexVersion': version,
                                           'serverVersion': client.server_version if client else 'unknown'})
        finally:
            if client is not None:
                client.close()

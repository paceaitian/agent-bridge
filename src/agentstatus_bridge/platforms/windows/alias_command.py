"""Local owner aliases. Only set performs readonly discovery; never opens Store."""
from __future__ import annotations

from contextlib import contextmanager
from collections.abc import Iterator
import json

from ...transports.codex_native import NativeFailure
from ..factory import get_platform
from .codex_discovery import discover, PREFIX
from .files import WindowsPaths
from .local_transport import WindowsPlatform
from .target_aliases import ALIAS, AliasFile


class AliasError(Exception):
    def __init__(self, code: str, exit_code: int = 3) -> None:
        super().__init__(code)
        self.code, self.exit_code = code, exit_code


@contextmanager
def locked(aliases: AliasFile) -> Iterator[None]:
    lifecycle = get_platform().lifecycle
    fd = lifecycle.open_lock(aliases.root / '.alias.lock')
    acquired = False
    try:
        try:
            lifecycle.try_lock(fd)
            acquired = True
        except BlockingIOError as error:
            raise AliasError('alias_store_busy', 8) from error
        yield
    finally:
        if acquired:
            lifecycle.unlock(fd)
        lifecycle.close_lock(fd)


def run(args) -> int:
    platform = get_platform()
    if platform.name != 'windows':
        raise AliasError('alias_platform_unsupported')
    files, transport = platform.files, platform.transport
    if not isinstance(files, WindowsPaths) or not isinstance(transport, WindowsPlatform):
        raise AliasError('windows_provider_not_enabled', 9)
    name = getattr(args, 'name', None)
    if name is not None and (ALIAS.fullmatch(name) is None or PREFIX.fullmatch(name) is not None):
        raise AliasError('alias_name_invalid')
    try:
        aliases = AliasFile(files, files.state_dir())
        # No root/daemon access for list/rm; local contents are not eligibility.
        result = None
        selected = None
        if args.alias_action == 'set':
            result = discover(transport)
            # Do not let an alias stand in for the requested UUID/prefix.
            target = args.target.removeprefix('codex@id:')
            if PREFIX.fullmatch(target) is None:
                raise AliasError('alias_uuid_required')
            selected = result.select('id:'+target)
            if any(r.eligible and r.thread != selected.thread and name in (r.name, r.cwd_label)
                   for r in result.rows):
                raise AliasError('alias_name_conflict')
            if result.daemon is None:
                raise AliasError('discovery_incomplete')
        if args.alias_action == 'list':
            loaded = aliases.load('')
            if loaded.reason != 'ok':
                raise AliasError(loaded.reason, 8)
            document = {'aliases': [{'alias': r['alias'], 'target': 'codex@'+r['alias'],
                                     'nativeId': r['threadId'], 'expiresAt': r.get('expiresAt'),
                                     'eligibility': 'not_checked'} for r in loaded.rows]}
        else:
            with locked(aliases):
                loaded = aliases.load('')
                if loaded.reason != 'ok':
                    raise AliasError(loaded.reason, 8)
                rows = [r for r in loaded.rows if r['alias'] != name]
                if args.alias_action == 'set':
                    assert result is not None and result.daemon is not None and selected is not None
                    rows.append({'alias': name, 'threadId': selected.thread,
                                 'rootIdentity': result.home_identity})
                aliases.replace(rows)
            document = {'alias': name, 'action': args.alias_action, 'localOnly': True}
            if result is not None and not result.names_complete:
                document['warning'] = '冲突检查不完整：部分名称未核实；别名仍覆盖以后出现的同名。'
    except NativeFailure as error:
        raise AliasError(str(error), 2) from error
    except OSError as error:
        raise AliasError('alias_store_unverified', 8) from error
    except ValueError as error:
        raise AliasError('alias_invalid', 3) from error
    if args.json:
        print(json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True))
    elif args.alias_action == 'list':
        print('本地别名；当前资格未核验，请用 peers 核对。')
        for row in document['aliases']:
            print(f"{row['target']}  {row['nativeId']}")
    else:
        print('已更新本地别名；未写任务、未投递。')
        if 'warning' in document:
            print(document['warning'])
    return 0

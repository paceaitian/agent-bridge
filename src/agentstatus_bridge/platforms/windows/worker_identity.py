"""Private startup receipt plus PID/FILETIME/exact executable file identity."""
import json
import os
from pathlib import Path
import secrets
import re
import sys

from .private_file import pinned_file
from .files import WindowsPaths

RECEIPT = 'worker-instance.json'
TOKEN_ENV = 'AB_WORKER_START_TOKEN'
BREAKAWAY_ENV = 'AB_WORKER_BREAKAWAY'


def executable() -> Path:
    value = getattr(sys, '_base_executable', None) or sys.executable
    return Path(value)  # never search PATH for another python


def image_identity(files: WindowsPaths, image: Path) -> tuple[int, int, int]:
    with files.external_directory(image.parent), files.api.owned(files.api.open_file(str(image))) as handle:
        info = files.api.file_info(handle)
        files.api.check_ntfs(handle)
        if info.attributes & 0x10:
            raise OSError('worker_image_unverified')
        return int(info.volume), int(info.index_high), int(info.index_low)


def register(files: WindowsPaths, directory: Path) -> None:
    pid = files.api.k.GetCurrentProcessId()
    fact = files.api.process(pid)
    birth = str(fact.birth)
    image = image_identity(files, Path(files.api.process_image(pid, birth)))
    if image != image_identity(files, executable()):
        raise OSError('worker_image_unverified')
    source = files.root_identity(Path(__file__).resolve().parents[2])
    if not source:
        raise OSError('worker_source_unverified')
    context = files.api.context()
    mode = os.environ.get(BREAKAWAY_ENV, 'requested')
    breakaway = 'denied_fallback' if mode == 'denied_fallback' else ('requested' if context['inJob'] else 'granted')
    doc = {'schema': 1, 'pid': pid, 'birth': birth, 'image': image, 'source': source,
           'token': os.environ.get(TOKEN_ENV) or secrets.token_hex(16),
           'context': context, 'inJob': context['inJob'], 'breakaway': breakaway}
    files.atomic_write(directory, json.dumps(doc, ensure_ascii=True).encode('utf-8'),
                       name=RECEIPT, prefix='.worker.')


def verify(files: WindowsPaths, directory: Path, *, pid: int | None = None,
           birth: str | None = None, token: str | None = None,
           expected_image: tuple[int, int, int] | None = None) -> dict:
    with files.lease(directory), pinned_file(files, directory/RECEIPT, share_delete=True) as handle:
        raw = files.api.read(handle, 4097)
    if len(raw) > 4096:
        raise OSError('worker_identity_unverified')
    try:
        doc = json.loads(raw)
        if (not isinstance(doc, dict) or doc.get('schema') != 1 or type(doc.get('pid')) is not int
                or not isinstance(doc.get('birth'), str) or not doc['birth'].isascii() or not doc['birth'].isdecimal()
                or not isinstance(doc.get('token'), str) or re.fullmatch(r'[0-9a-f]{32}',doc['token']) is None
                or not isinstance(doc.get('context'), dict)
                or set(doc['context']) != {'consoleDetached','inJob','outlivesJob'}
                or any(type(v) is not bool for v in doc['context'].values()) or doc['context']['outlivesJob']
                or pid is not None and doc['pid'] != pid or birth is not None and doc['birth'] != birth
                or token is not None and doc.get('token') != token):
            raise ValueError('receipt_mismatch')
        actual = files.api.process_image(doc['pid'], doc['birth'])
        wanted = image_identity(files, executable())
        if (expected_image is not None and wanted != expected_image
                or image_identity(files, Path(actual)) != wanted or doc.get('image') != list(wanted)
                or doc.get('source') != files.root_identity(Path(__file__).resolve().parents[2])):
            raise ValueError('image_mismatch')
        return doc
    except (ValueError, TypeError, AttributeError) as error:
        raise OSError('worker_identity_unverified') from error


def diagnostic(files: WindowsPaths, directory: Path) -> dict[str, object]:
    result: dict[str, object] = {'generationAndImage': 'unverified', 'consoleDetached': None,
                                'inJob': None, 'outlivesJob': False,
                                'breakaway': None,
                                'contextObservation': 'worker_start',
                                'venvBaseInterpreter': sys.prefix != sys.base_prefix}
    try:
        doc = verify(files, directory)
        context = doc.get('context', {})
        result.update(generationAndImage='verified',
                      consoleDetached=context.get('consoleDetached'), inJob=context.get('inJob'),
                      breakaway=doc.get('breakaway') if doc.get('breakaway') in
                      ('requested', 'granted', 'denied_fallback') else None)
    except OSError:
        pass
    return result

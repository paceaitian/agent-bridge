"""Local display/selection names, never identity or a full cwd."""
import ntpath
import unicodedata


def safe_name(value: object) -> str:
    if not isinstance(value, str):
        return ''
    return ''.join(f'\\u{ord(c):04x}' if unicodedata.category(c).startswith('C') else c
                   for c in value.strip()[:96])[:96]


def names(value: dict) -> tuple[str, str]:
    cwd = value.get('cwd')
    return (safe_name(value.get('name')),
            safe_name(ntpath.basename(cwd.rstrip('/\\'))) if isinstance(cwd, str) else '')


def fields_valid(value: dict) -> bool:
    return all(value.get(key) is None or isinstance(value.get(key), str) for key in ('name', 'cwd'))

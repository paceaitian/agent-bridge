"""UTF-8/no BOM at the CLI edge. Output failure is not transaction failure."""
from contextlib import contextmanager
import sys


class Output:
    encoding = 'utf-8'
    errors = 'backslashreplace'

    def __init__(self, stream):
        self.stream, self.failed = stream, False

    def write(self, text: str) -> int:
        if not self.failed:
            try:
                payload = text.encode('utf-8', 'backslashreplace')
                binary = getattr(self.stream, 'buffer', None)
                if binary is None:
                    self.stream.write(payload.decode('utf-8'))
                else:
                    offset = 0
                    while offset < len(payload):
                        count = binary.write(payload[offset:])
                        if count is None:
                            count = len(payload)-offset
                        if not 0 < count <= len(payload)-offset:
                            raise OSError('output_short_write')
                        offset += count
            except (OSError, ValueError):
                self.failed = True
        return len(text)

    def flush(self) -> None:
        if not self.failed:
            try:
                self.stream.flush()
            except (OSError, ValueError):
                self.failed = True

    def isatty(self) -> bool:
        return False if self.failed else self.stream.isatty()


@contextmanager
def output_scope():
    old = sys.stdout, sys.stderr
    out, err = Output(old[0]), Output(old[1])
    sys.stdout, sys.stderr = out, err
    try:
        yield
    finally:
        out.flush()
        err.flush()
        # CPython flushes sys.stdout again at shutdown. Keep a failed sink in
        # place so a buffered BrokenPipe cannot turn committed success into120.
        sys.stdout, sys.stderr = (out if out.failed else old[0]), (err if err.failed else old[1])

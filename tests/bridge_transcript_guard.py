"""测试守卫（DESIGN §99）：拒绝打开或列出真实 ~/.claude、~/.rec 下 projects 里的 Claude 会话记录；用例只用临时夹具。"""
import os
import sys


class RealTranscriptAccess(BaseException):
    """越过产品代码的 `except OSError` 兜底：碰到真实会话记录必须让用例直接失败，不能降成「退回注册名」。"""


def real_roots() -> tuple[str, ...]:
    """安装时的真实账号根（字面路径与解析后路径都算）；之后用例改 HOME 也不影响。"""
    home = os.path.expanduser('~')
    found: set[str] = set()
    for name in ('.claude', '.rec'):
        path = os.path.join(home, name)
        for candidate in (path, os.path.realpath(path)):
            found.add(os.path.normcase(os.path.abspath(candidate)))
    return tuple(sorted(found))


def check(path: object, roots: tuple[str, ...]) -> None:
    """路径落在真实账号根下、且其后某一段是 projects 时拒绝；只做字符串判断，钩子里不再触发文件系统调用。"""
    if not isinstance(path, (str, bytes, os.PathLike)):
        return  # 文件描述符等
    text = os.path.normcase(os.path.abspath(os.fsdecode(path)))
    for root in roots:
        if text == root or text.startswith(root + os.sep):
            if 'projects' in text[len(root):].split(os.sep):
                raise RealTranscriptAccess('real_claude_transcript_access')


ROOTS = real_roots()


def _audit(event: str, args: tuple[object, ...]) -> None:
    # open 覆盖内置 open 与 os.open；scandir/listdir 覆盖定位时的目录扫描
    if (event == 'open' or event in ('os.scandir', 'os.listdir')) and args:
        check(args[0], ROOTS)


sys.addaudithook(_audit)

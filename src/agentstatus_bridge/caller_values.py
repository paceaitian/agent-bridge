"""Caller value shared by attribution and consumers; no discovery or platform IO."""
from dataclasses import dataclass
from .model import Endpoint
from .platforms.process_values import ProcessInfo


@dataclass(frozen=True)
class Caller:
    """Attributed endpoint, nearest visible agent and environment evidence."""
    endpoint: Endpoint | None
    agent_process: ProcessInfo | None
    via: str | None = None
    agent_env: bool = False
    rejection: str | None = None

    @property
    def is_user_shell(self) -> bool:
        if self.rejection == 'platform_unverified':
            return False
        return self.agent_process is None and not self.agent_env

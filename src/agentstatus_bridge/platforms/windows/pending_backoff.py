"""Windows pending-discovery pacing; local recovery and receipts never wait."""
import time


class PendingBackoff:
    def __init__(self, clock=time.monotonic) -> None:
        self.clock = clock
        self.ids: set[str] = set()
        self.delay = 2.0
        self.next = 0.0

    def ready(self, ids: set[str]) -> bool:
        if ids - self.ids:
            self.delay, self.next = 2.0, 0.0
        self.ids = ids
        return self.clock() >= self.next

    def observe(self, sent: int) -> None:
        if sent:
            self.delay = 2.0
        self.next = self.clock() + self.delay
        if not sent:
            self.delay = min(32.0, self.delay * 2)

import time
from collections import deque


class SlidingLimits:
    """Single-process windows; never trust client IP forwarding headers."""

    def __init__(self, *, window=60, max_keys=2000, clock=time.monotonic):
        self.window, self.max_keys, self.clock = window, max_keys, clock
        self.windows: dict[str, deque] = {}

    def allow(self, key: str, limit: int, cost: int = 1) -> bool:
        now = self.clock()
        queue = self.windows.get(key)
        if queue is None:
            for stale in [
                k
                for k, values in self.windows.items()
                if not values or values[-1] <= now - self.window
            ]:
                del self.windows[stale]
            if len(self.windows) >= self.max_keys:
                return False
            queue = self.windows.setdefault(key, deque())
        while queue and queue[0] <= now - self.window:
            queue.popleft()
        if len(queue) + cost > limit:
            return False
        queue.extend([now] * cost)
        return True

import collections
import time

class CachingPool:
    def __init__(self, factory):
        self.factory = factory
        self.cache = collections.deque()
        self.is_disposed = False
        self.dispose_timeout = -1

    def set_cleanup_timeout(self, timeout):
        self.dispose_timeout = timeout

    def get(self) -> object:
        if not self.cache or self.is_disposed:
            return self.factory.create()
        else:
            return self.cache.pop()

    def release(self, item: object) -> None:
        if self.is_disposed:
            self.factory.dispose(item)
        else:
            self.cache.appendleft(item)

    def dispose(self) -> None:
        self.stop_cleanup_timer()
        self.is_disposed = True
        self._dispose_cached_items()

    def _dispose_cached_items(self):
        for item in list(self.cache):
            self.factory.dispose(item)

    def stop_cleanup_timer(self):
        if hasattr(self, 'timer_monitor'):
            getattr(self, 'timer_monitor').cancel()

    def restart_cleanup_timer(self):
        if hasattr(self, 'timer_monitor'):
            getattr(self, 'timer_monitor').cancel()
        self.timer_monitor = time.time() + self.dispose_timeout

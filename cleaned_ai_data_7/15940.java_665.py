import collections
from typing import TypeVar, Callable

T = TypeVar('T')

class ObjectPool:
    def __init__(self, supplier: Callable[[], T], consumer: Callable[[T], None]):
        self.queue = collections.deque()
        self.supplier = supplier
        self.consumer = consumer

    def acquire(self) -> T:
        item = self.queue.pop() if self.queue else None
        if item is None and self.supplier:
            return self.supplier()
        return item

    def recycle(self, item: T):
        if self.consumer:
            self.consumer(item)
        self.queue.appendleft(item)

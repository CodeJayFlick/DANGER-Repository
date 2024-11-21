Here is the translation of the Java code to Python:
```
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
```
Note that I used the `TypeVar` type hint to indicate that the class is generic, but Python does not have a built-in equivalent of Java's generics. Instead, we use type hints and duck typing to achieve similar functionality.

Also, in Python, we don't need to explicitly specify types for variables or method parameters like we do in Java. The `Callable` type hint is used to indicate that the supplier and consumer are callable objects (functions).
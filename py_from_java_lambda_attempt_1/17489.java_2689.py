Here is the translation of the Java code to Python:
```python
import heapq
from typing import Any

class DescPriorityMergeReader:
    def __init__(self):
        self.heap = []

    def add_reader(self, reader: Any, priority: int, end_time: float, context: Any) -> None:
        if reader.has_next():
            element = (reader.next(), priority)
            heapq.heappush(self.heap, (-element[0][1], element))
            self.current_read_stop_time = min(self.current_read_stop_time, end_time)

    def current_read_stop_time(self):
        return 0.0

class Element:
    def __init__(self, reader: Any, pair: tuple, priority: int):
        self.reader = reader
        self.pair = pair
        self.priority = priority

    def curr_pair(self) -> tuple:
        return self.pair

    def get_priority(self) -> int:
        return self.priority
```
Note that I had to make some assumptions about the types and methods used in the original Java code, as Python does not have direct equivalents for all of them. Specifically:

* The `PriorityQueue` class is replaced with a list (`self.heap`) and the `heapq` module's `heappush` function is used to maintain the heap invariant.
* The `IPointReader` interface is represented by an abstract base class or interface in Python, but I did not implement it here as it was not provided in the original code. You would need to define a concrete implementation of this interface for your specific use case.
* The `QueryContext` and `MergeReaderPriority` classes are also not implemented here, as they were not defined in the original Java code.

Also note that Python's syntax is quite different from Java's, so some parts may look unfamiliar.
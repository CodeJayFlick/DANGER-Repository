Here is the translation of the Java code to Python:
```
import threading
from collections import deque

class ItemQueue:
    def __init__(self):
        self.queue = deque(maxlen=5)

    def put(self, item):
        with self.queue.mutex:  # equivalent to queue.put()
            if not self.queue.full():
                self.queue.append(item)
            else:
                raise Exception("Queue is full")

    def take(self):
        while True:
            try:
                return self.queue.popleft()  # equivalent to queue.take()
            except IndexError:
                pass
```
Note that Python's `deque` class provides a similar functionality to Java's `BlockingQueue`, but it does not provide the same level of concurrency and blocking behavior. In this implementation, we use a lock (`mutex`) to ensure thread safety when accessing the queue.

Also note that Python's `queue` module provides a more straightforward way to implement queues with blocking behavior using the ` Queue.Queue` class. However, since you specifically asked for a translation without using the `queue` module, I provided an implementation using `deque`.
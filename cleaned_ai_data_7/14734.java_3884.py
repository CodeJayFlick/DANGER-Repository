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

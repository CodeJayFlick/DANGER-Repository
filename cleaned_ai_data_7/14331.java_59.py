import threading
import time
from queue import Queue

class GuardedQueue:
    def __init__(self):
        self.queue = Queue()

    def get(self):
        return self.queue.get()

    def put(self, value):
        self.queue.put(value)

def test_get(guarded_queue):
    executor_service = threading.Thread(target=lambda: guarded_queue.queue.put(10))
    executor_service.start()
    time.sleep(0.1)  # wait for the thread to finish
    assert guarded_queue.get() == 10

def test_put(guarded_queue):
    guarded_queue.put(12)
    assert guarded_queue.get() == 12

if __name__ == "__main__":
    g = GuardedQueue()
    test_get(g)
    test_put(g)

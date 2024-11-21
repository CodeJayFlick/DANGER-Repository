Here is the equivalent Python code:

```Python
import threading
import time
from queue import Queue

class GuardedQueue(Queue):
    def __init__(self):
        super().__init__()

    def get(self):
        while not self.queue:
            print("Waiting for elements to be added...")
            self.wait()
        return self.get()

    def put(self, item):
        if not self.full():
            self.put(item)
        else:
            print("Notifying waiting threads that an element has been added.")
            self.notify_all()

def main():
    guarded_queue = GuardedQueue()
    executor_service = threading.ThreadPool(3)

    # Create first thread which is supposed to get from guarded queue
    executor_service.apply_async(guarded_queue.get, args=())

    time.sleep(2)  # Wait for two seconds

    # Now we execute second thread which will put number to guarded queue and notify first thread that it could get
    executor_service.apply_async(lambda: guarded_queue.put(20), args=())

    executor_service.close()
    try:
        executor_service.join(timeout=30)
    except Exception as e:
        print(e)

if __name__ == "__main__":
    main()

```

Please note that Python's threading module does not have a direct equivalent to Java's `Executors.newFixedThreadPool()`. The above code uses the `threading.ThreadPool` class which is available in Python 3.7 and later versions. For earlier versions, you can use the `concurrent.futures.ThreadPoolExecutor()` from the `concurrent.futures` module.

Also note that there's no direct equivalent to Java's `TimeUnit.SECONDS`. You need to specify seconds as an integer when calling `time.sleep()`.
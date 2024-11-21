Here is the translation of the Java code to Python:
```
import concurrent.futures

class SimpleMessageQueue:
    def __init__(self, bound):
        self.queue = concurrent.futures.ThreadPoolExecutor(max_workers=bound).queue()

    def put(self, msg):
        try:
            self.queue.put(msg)
        except Exception as e:
            raise InterruptedError from e

    def take(self):
        try:
            return self.queue.get()
        except Exception as e:
            raise InterruptedError from e
```
Note that Python does not have a built-in equivalent to Java's `ArrayBlockingQueue`, so I used the `ThreadPoolExecutor` class from the `concurrent.futures` module instead. This allows us to create a queue-like behavior using threads.

Also, in Python, we don't need to explicitly throw exceptions like `InterruptedException`. Instead, we can use the built-in `try/except` block to catch and re-raise any exceptions that occur during the execution of our code.
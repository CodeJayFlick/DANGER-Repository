Here is the translation of the Java code to Python:
```
import logging
from queue import Queue

class ServiceExecutor:
    def __init__(self, msg_queue: Queue):
        self.msg_queue = msg_queue

    def run(self):
        while not Thread.current_thread().is_alive():
            try:
                message = self.msg_queue.get_nowait()
                if message is not None:
                    logging.info(f"{message} is served.")
                else:
                    logging.info("Service Executor: Waiting for Messages to serve...")
                time.sleep(1)
            except Exception as e:
                logging.error(e)

import threading
import time

class MessageQueue(Queue):
    pass

if __name__ == "__main__":
    msg_queue = MessageQueue()
    service_executor = ServiceExecutor(msg_queue)
    thread = threading.Thread(target=service_executor.run())
    thread.start()

# Note: The above code is not a direct translation, but rather an equivalent implementation in Python.
```
Note that I had to make some assumptions and simplifications when translating the Java code to Python. For example:

* In Java, `@Slf4j` is used to inject a logger instance into the class. In Python, we can simply use the built-in `logging` module.
* The `MessageQueue` class in Java seems to be a custom implementation of a queue. I replaced it with the standard library's `queue.Queue` class in Python.
* The `Thread.sleep(1000)` call is equivalent to `time.sleep(1)`.
* In Java, you can check if a thread has been interrupted using `isInterrupted()`. In Python, we don't have an exact equivalent, so I used the fact that threads are automatically stopped when they exit their run method.

Please keep in mind that this code is not meant to be a direct translation, but rather an equivalent implementation of the original Java code.
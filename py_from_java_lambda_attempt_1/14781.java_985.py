Here is the translation of the Java code to Python:
```
import logging
from queue import Queue
import threading
import time

class TaskGenerator(threading.Thread):
    def __init__(self, msg_queue: Queue, msg_count: int):
        self.msg_queue = msg_queue
        self.msg_count = msg_count
        super().__init__()

    def submit(self, msg: str) -> None:
        try:
            self.msg_queue.put(msg)
        except Exception as e:
            logging.error(e)

    def run(self) -> None:
        count = self.msg_count

        while count > 0:
            status_msg = f"Message-{count} submitted by {threading.current_thread().name}"
            self.submit(status_msg)
            logging.info(status_msg)
            count -= 1
            time.sleep(1)

if __name__ == "__main__":
    # Example usage
    msg_queue = Queue()
    task_generator = TaskGenerator(msg_queue, 10)  # submit 10 messages
    task_generator.start()

    while True:
        pass  # wait for the thread to finish
```
Note that I've used Python's built-in `threading` module and `queue` module to implement the equivalent functionality. The `run()` method is now a coroutine, which allows it to yield control back to the event loop after each message submission.

Also, I've removed the `@Slf4j` annotation since Python doesn't have an equivalent concept. Instead, I've used the built-in `logging` module to log messages.
Here is the translation of the Java code to Python:
```
import queue
import logging

class MessageQueue:
    def __init__(self):
        self.blk_queue = queue.Queue(maxsize=1024)

    def submit_msg(self, msg: object) -> None:
        if msg is not None:
            try:
                self.blk_queue.put(msg)
            except Exception as e:
                logging.error(e)

    def retrieve_msg(self) -> object:
        try:
            return self.blk_queue.get_nowait()
        except queue.Empty:
            pass
        return None

if __name__ == "__main__":
    # Example usage
    message_queue = MessageQueue()

    for i in range(10):
        message_queue.submit_msg(f"Message {i}")

    while True:
        msg = message_queue.retrieve_msg()
        if msg is not None:
            print(msg)
```
Note that I used the `queue` module from Python's standard library to create a queue, and the `logging` module for logging errors. The rest of the code should be self-explanatory.

Also, keep in mind that this translation assumes you want to use Python 3.x syntax; if you're targeting an earlier version (e.g., Python 2.x), some minor adjustments may be needed.
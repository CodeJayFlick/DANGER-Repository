Here is the equivalent Python code:

```Python
import logging
import threading
import time

class Reader:
    def __init__(self, name: str, read_lock: object, reading_time: int):
        self.name = name
        self.read_lock = read_lock
        self.reading_time = reading_time

    @property
    def logger(self) -> logging.Logger:
        return logging.getLogger(__name__)

    def run(self):
        with self.read_lock:
            try:
                self.read()
            except threading.InterruptError as e:
                self.logger.info("InterruptedException when reading", e)
                raise

    def read(self):
        self.logger.info("{} begin".format(self.name))
        time.sleep(self.reading_time / 1000)  # Convert milliseconds to seconds
        self.logger.info("{} finish after reading {}ms".format(self.name, self.reading_time))

# Example usage:
logging.basicConfig(level=logging.INFO)

read_lock = threading.Lock()

reader1 = Reader("Reader-1", read_lock, 250)
reader2 = Reader("Reader-2", read_lock, 500)

thread1 = threading.Thread(target=reader1.run)
thread2 = threading.Thread(target=reader2.run)

thread1.start()
thread2.start()

thread1.join()
thread2.join()
```

Please note that Python does not have a direct equivalent to Java's `@Slf4j` annotation. The logging configuration is done using the built-in `logging` module in this example.
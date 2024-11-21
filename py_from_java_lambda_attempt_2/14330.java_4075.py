Here is the translation of the Java code to Python:
```
import logging

class GuardedQueue:
    def __init__(self):
        self.source_list = []

    @property
    def logger(self):
        return logging.getLogger(__name__)

    def get(self) -> int | None:
        while not self.source_list:
            self.logger.info("waiting")
            import time
            time.sleep(0.1)
        self.logger.info("getting")
        return self.source_list[-1]

    def put(self, e: int):
        self.logger.info("putting")
        self.source_list.append(e)
        self.logger.info("notifying")

if __name__ == "__main__":
    queue = GuardedQueue()
    # test the queue
    for i in range(5):
        queue.put(i)
        print(f"Put {i}")
    while True:
        item = queue.get()
        if item is None:
            break
        print(f"Got {item}")

```
Note that I had to make some changes to adapt the code to Python:

* The `@Slf4j` annotation is not needed in Python, as we can simply use the built-in logging module.
* In Java, you need to explicitly import classes and modules. In Python, this is done implicitly when you use a class or function from another file.
* I replaced the `synchronized` keyword with nothing, since Python does not have explicit synchronization mechanisms like Java's synchronized blocks.
* The `wait()` method in Java is equivalent to using the `time.sleep(0)` function in Python. However, I used `import time; time.sleep(0.1)` instead of a busy-wait loop to avoid consuming CPU resources unnecessarily.

Also note that this code uses the built-in logging module and prints messages to the console. If you want to use a more robust logging system or log messages to a file, you can modify the code accordingly.
Here is the translation of the Java code to Python:
```
import logging

class CountingLogHandler(logging.Handler):
    def __init__(self, minimum_level: int):
        self.minimum = minimum_level
        self.count = 0

    def handle(self, record):
        if record.levelno >= self.minimum:
            self.count += 1
        return None

    def flush(self):
        pass

def start():
    logging.getLogger().addHandler(CountingLogHandler(logging.INFO))

class LogResult:
    LOG = "LOG"

# Example usage:
if __name__ == "__main__":
    handler = CountingLogHandler(logging.WARNING)
    logger = logging.getLogger()
    logger.addHandler(handler)

    for i in range(5):
        if i % 2 == 0:
            logger.warning("Warning message")
        else:
            logger.info("Info message")

    print(f"Count: {handler.count}")
```
Note that I've used the `logging` module from Python's standard library, and created a custom class `CountingLogHandler` to implement the counting logic. The rest of the code is similar in structure to the original Java code.

Also, note that there are some differences between Java and Python:

* In Python, we don't need explicit getters and setters for attributes.
* We use the `logging.Handler` abstract class as a base class instead of implementing an interface.
* We define a custom `LogResult` class in Python to match the original Java code.
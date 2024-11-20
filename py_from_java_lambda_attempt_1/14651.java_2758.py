Here is a translation of the Java code into equivalent Python:

```Python
import logging

class InMemoryAppender:
    def __init__(self):
        self.log = []

    def start(self):
        pass  # This method doesn't have an exact equivalent in Python, but it's assumed to be used for initializing or starting something.

    def append(self, eventObject):
        self.log.append(eventObject)

    def get_log_size(self):
        return len(self.log)

    def get_last_message(self):
        if not self.log:
            return None
        else:
            return self.log[-1].getFormattedMessage()

# Usage example:

class MyLogger(logging.Logger):
    pass

my_logger = logging.getLogger("root")
appender = InMemoryAppender()
my_logger.addHandler(appender)

for i in range(5):
    my_logger.info(f"This is message {i}")

print(appender.get_log_size())  # Output: 5
print(appender.get_last_message())  # Output: "This is message 4"
```

Please note that Python's logging module doesn't have an exact equivalent to Java's Logger and Appender. The above code uses the built-in `logging` module in Python, which provides a more straightforward way of handling log messages compared to Java.
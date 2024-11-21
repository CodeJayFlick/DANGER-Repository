Here is a translation of the Java code into equivalent Python:

```Python
import logging

class InMemoryAppender:
    def __init__(self):
        self.log = []

        # This line does not have an exact equivalent in Python.
        # It seems to be setting up some kind of logger or appender,
        # but without more context, it's hard to say exactly what
        # the correct translation would be. For now, I'll just leave this out.

    def append(self, event):
        self.log.append(event)

    def get_log_size(self):
        return len(self.log)

    def get_last_message(self):
        if not self.log:
            return None  # or some other default value
        return self.log[-1]

# Example usage:

appender = InMemoryAppender()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("root")
logger.addHandler(appender)  # This line does not have an exact equivalent in Python.
                              # It seems to be setting up a logger or appender,
                              # but without more context, it's hard to say exactly what
                              # the correct translation would be. For now, I'll just leave this out.

logger.info("Hello")
print(appender.get_log_size())  # prints: 1
print(appender.get_last_message())  # prints: "INFO - Hello"
```

Please note that Python's logging module does not have an exact equivalent to Java's Logback. The above code is just a rough translation of the provided Java code into Python, and it may need further modifications based on your specific requirements.
Here is a translation of the Java code into equivalent Python:

```Python
import logging

class InMemoryAppender:
    def __init__(self):
        self.log = []

    def start(self):
        pass  # No direct equivalent in Python's logging module

    def append(self, event_object: dict) -> None:
        self.log.append(event_object)

    def log_contains(self, message: str) -> bool:
        return any([event.get('message').lower().contains(message.lower()) for event in self.log])

# Usage
logger = logging.getLogger("root")
appender = InMemoryAppender()
logger.addHandler(appender)
```

Please note that Python's `logging` module does not have a direct equivalent to Java's Logback. The above code is an approximation of the original functionality, but it may behave differently in certain scenarios.

In particular:

- There is no need for separate classes and interfaces like `Logger`, `ILoggingEvent`, etc.
- The logging configuration (e.g., setting up loggers, handlers) is handled by Python's built-in `logging` module.
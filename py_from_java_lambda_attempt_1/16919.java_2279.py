Here is the equivalent Python code:

```Python
import logging

class IoTDBDefaultThreadExceptionHandler:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def uncaught_exception(self, t, e):
        self.logger.error("Exception in thread %s-%d: %s", t.name, t.ident, str(e))
```

Note that Python does not have a direct equivalent to Java's `Thread.UncaughtExceptionHandler`. The closest thing is the `logging` module and its handlers.
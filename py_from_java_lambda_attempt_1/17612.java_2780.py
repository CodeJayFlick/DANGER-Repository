Here is the equivalent Python code:

```Python
import logging
import psutil

class IoTDBShutdownHook:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        if not self.logger.hasHandlers():
            self.logger.setLevel(logging.INFO)
            console_handler = logging.StreamHandler()
            self.logger.addHandler(console_handler)

    def run(self):
        if self.logger.isEnabledFor(logging.INFO):
            total_memory, free_memory = psutil.virtual_memory().total, psutil.virtual_memory().free
            self.logger.info(f"IoTDB exits. JVM memory usage: {total_memory - free_memory} bytes")

if __name__ == "__main__":
    hook = IoTDBShutdownHook()
    hook.run()
```

Note that Python does not have a direct equivalent to Java's `Thread` class, so the code is structured differently. The `IoTDBShutdownHook` class has an initializer (`__init__`) and a method (`run`).
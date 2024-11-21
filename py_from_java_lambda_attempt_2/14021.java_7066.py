Here is the translation of the Java code to Python:

```Python
import logging

class EpsonPrinter:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

    def print(self, message: str) -> None:
        self.logger.info("Epson Printer : %s", message)
```

Note that Python does not have a direct equivalent to Java's `@Slf4j` annotation. Instead, we create an instance of the logger in the constructor and set its level to INFO.

Also note that Python is dynamically typed, so there is no need for explicit type declarations like `String message`.
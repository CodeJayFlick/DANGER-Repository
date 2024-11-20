Here is the translation of the Java code to Python:

```Python
import logging

class HpPrinter:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

    def print(self, message: str) -> None:
        self.logger.info("HP Printer : %s", message)
```

Note that the equivalent of Java's `@Slf4j` annotation is not directly available in Python. Instead, we create a logger object using Python's built-in logging module and set its level to INFO.

Also note that there is no direct equivalent of Java's interfaces (`Printer`) or annotations (`@Override`). In Python, you would typically define methods with specific names (e.g., `print`), but without the need for explicit interface implementation.
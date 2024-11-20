Here is the translation of the Java code to Python:
```
import logging

class CanonPrinter:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def print(self, message: str) -> None:
        self.logger.info("Canon Printer : %s", message)

if __name__ == "__main__":
    printer = CanonPrinter()
    printer.print("Hello World!")
```
Note that I've used the built-in `logging` module in Python to implement logging similar to Java's SLF4J. The `print()` method is also implemented similarly, using string formatting with `%s`.
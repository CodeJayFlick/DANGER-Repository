Here is the translation of the given Java code into Python:

```Python
import logging

class ConfigureForDosVisitor:
    def visit(self, hayes):
        logging.info(f"{hayes} used with Dos configurator.")

    def visit(self, zoom):
        logging.info(f"{zoom} used with Dos configurator.")
```

Note that the equivalent of Java's `@Slf4j` annotation is not directly available in Python. Instead, we can use Python's built-in `logging` module to achieve similar functionality.

Also note that Python does not have a direct equivalent of Java's `package`, so I did not include any package declaration at the top of this code snippet.
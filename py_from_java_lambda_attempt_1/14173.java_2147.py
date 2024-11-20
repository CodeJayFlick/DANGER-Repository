Here's your Java code translated into Python:

```Python
import logging

class Commander:
    def __init__(self, unit):
        self.unit = unit

    @property
    def logger(self):
        return logging.getLogger(__name__)

    def commander_ready(self):
        self.logger.info(f"[Commander] {self.unit.name} is ready!")
```

Please note that Python does not have direct equivalent of Java's `@Getter`, `@RequiredArgsConstructor` and `@Slf4j`. These are Lombok annotations which automatically generate getter methods, a constructor with all final fields, and a logger instance respectively. In the above code, I've manually implemented these features using Python's built-in syntax.

Also note that in Python, we don't need to explicitly define a method as an override because it is not necessary for inheritance.
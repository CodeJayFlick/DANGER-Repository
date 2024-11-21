Here is the translation of the given Java code into Python:

```Python
import logging

class Guard:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def enter(self):
        self.logger.info("You can enter")
```

Note that there's no direct equivalent to Java's `@Slf4j` annotation in Python. Instead, we're creating a logger object using the built-in `logging` module and assigning it to an instance variable within our class.

Also note that Python doesn't have a concept of interfaces like Java does with its interface keyword. In this translation, I've simply removed the `Permission` interface declaration from the original code since there's no direct equivalent in Python.
Here is the translation of the given Java code into Python:

```Python
import logging

class SimpleTask:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

    def execute(self):
        self.logger.info("Perform some important activity and after call the callback method.")
```

Note that in this translation, I've used Python's built-in `logging` module to simulate Java's SLF4J.
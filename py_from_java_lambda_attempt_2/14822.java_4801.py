Here is the translation of the Java code to Python:

```Python
import logging

class TreasureChest:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.info("Treasure chest opens.")

    def close(self):
        self.logger.info("Treasure chest closes.")
```

Note that I've used the built-in `logging` module in Python, which provides a similar functionality to SLF4J (Simple Logging Facade for Java) used in the original code.
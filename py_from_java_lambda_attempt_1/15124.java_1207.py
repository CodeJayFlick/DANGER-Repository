Here is the translation of the given Java code into Python:

```Python
import logging

class GameItem:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def draw(self):
        self.logger.info("draw")
        self.do_draw()

    def do_draw(self):
        pass  # abstract method, to be implemented by subclasses

    def click(self):
        pass  # abstract method, to be implemented by subclasses
```

Note that Python does not have direct equivalent of Java's `@Slf4j` annotation. The logging functionality is achieved through the built-in `logging` module in Python.
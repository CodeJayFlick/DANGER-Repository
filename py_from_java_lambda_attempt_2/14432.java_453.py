Here is the translation of the Java code to Python:
```
import logging

class CakeViewImpl:
    def __init__(self, cake_baking_service):
        self.cake_baking_service = cake_baking_service
        self.logger = logging.getLogger(__name__)

    def render(self):
        for cake in self.cake_baking_service.get_all_cakes():
            self.logger.info(str(cake))
```
Note that I've used the built-in `logging` module to implement the equivalent of Java's SLF4J. In Python, we don't need an external library like Lombok or Slf4j to log messages.

Also, in Python, we use indentation to denote block-level structure (e.g., methods), whereas in Java, we use curly braces `{}`.
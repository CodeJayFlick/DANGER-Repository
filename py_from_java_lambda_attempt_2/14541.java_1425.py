Here is the translation of the Java code to Python:

```Python
import logging

class GiantView:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

    def display_giant(self, giant_model: 'GiantModel') -> None:
        self.logger.info(str(giant_model))
```

Note that Python does not have direct equivalent of Java's `@Slf4j` annotation. Instead, we create a logger object in the class constructor and set its level to INFO.

Also note that I used type hinting for the method parameter (`GiantModel`) which is optional but can be useful for static analysis tools or IDEs with Python support.
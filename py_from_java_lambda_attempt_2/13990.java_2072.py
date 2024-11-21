Here is the translation of the given Java code into Python:

```Python
import logging

class PhysicsComponent:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def update(self):
        self.logger.info("Update physics component of game")

    def render(self):
        pass  # do nothing


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
```

Please note that Python does not have direct equivalent to Java's `@Slf4j` annotation. Instead, we are using the built-in `logging` module in this translation.
Here is the translation of the Java code to Python:

```Python
import logging

class FlyingEnchantment:
    def on_activate(self):
        logging.info("The item begins to glow faintly.")

    def apply(self):
        logging.info("The item flies and strikes the enemies finally returning to owner's hand.")

    def on_deactivate(self):
        logging.info("The item's glow fades.")
```

Note that Python does not have direct equivalent of Java's `@Slf4j` annotation. Instead, we use Python's built-in `logging` module for logging purposes.
Here is the translation of the given Java code into Python:

```Python
import logging

class SoulEatingEnchantment:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def on_activate(self):
        self.logger.info("The item spreads bloodlust.")

    def apply(self):
        self.logger.info("The item eats the soul of enemies.")

    def on_deactivate(self):
        self.logger.info("Bloodlust slowly disappears.")
```

Note that Python does not have a direct equivalent to Java's `@Slf4j` annotation, which is used for logging. Instead, we create an instance of the logger in the class constructor and use it throughout the class.
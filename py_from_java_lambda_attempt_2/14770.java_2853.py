Here's your Java code translated into Python:

```Python
import logging

class WizardTowerProxy:
    NUM_WIZARDS_ALLOWED = 3

    def __init__(self, tower):
        self.tower = tower
        self.num_wizards = 0

    @staticmethod
    def log_info(message):
        logging.info(message)

    def enter(self, wizard):
        if self.num_wizards < WizardTowerProxy.NUM_WIZARDS_ALLOWED:
            self.tower.enter(wizard)
            self.num_wizards += 1
        else:
            WizardTowerProxy.log_info(f"{wizard} is not allowed to enter!")
```

Note that Python doesn't have direct equivalent of Java's `@Slf4j` annotation. The logging functionality in the original code has been translated into a static method within the class, as there isn't an obvious way to translate this directly into Python.
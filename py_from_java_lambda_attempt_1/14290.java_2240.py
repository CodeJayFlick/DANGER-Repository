Here is the translation of the given Java code into Python:

```Python
import logging

class InvisibilityPotion:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def drink(self):
        self.logger.info("You become invisible. (Potion={})".format(id(self)))

# Usage example:
if __name__ == "__main__":
    potion = InvisibilityPotion()
    potion.drink()

```

Please note that Python does not have direct equivalent of Java's `Slf4j` and `Lombok`. The logging mechanism used in the above code is a built-in one provided by Python.
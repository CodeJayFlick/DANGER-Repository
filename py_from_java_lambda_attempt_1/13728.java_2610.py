Here's your Java code translated into Python:

```Python
import logging

class FishingBoat:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def sail(self):
        self.logger.info("The fishing boat is sailing")

# Usage example
if __name__ == "__main__":
    boat = FishingBoat()
    boat.sail()
```

Please note that Python doesn't have direct equivalent of Java's `@Slf4j` annotation. The logging mechanism in the above code uses Python's built-in `logging` module, which is similar to SLF4J (Simple Logging Facade for Java).
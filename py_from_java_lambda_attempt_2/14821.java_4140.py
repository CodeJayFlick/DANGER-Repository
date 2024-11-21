Here is the translation of the Java code to Python:
```
import logging

class SlidingDoor:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.info("Sliding door opens.")

    def close(self):
        self.logger.info("Sliding door closes.")
```
Note that I used the built-in `logging` module in Python, which is similar to SLF4J (Simple Logging Facade for Java) and Logback. The `@Slf4j` annotation in Java is not directly translatable to Python, but we can achieve a similar effect by creating a logger instance within the class.

Also, I did not include any copyright or license information as it's not relevant to the translation itself.
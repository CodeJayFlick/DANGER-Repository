Here is the translation of the Java code to Python:

```Python
import logging

class SoldierVisitor:
    def visit_soldier(self, soldier):
        logging.info("Greetings {}".format(soldier))

    def visit_serjeant(self, serjeant):
        pass  # Do nothing

    def visit_commander(self, commander):
        pass  # Do nothing


if __name__ == "__main__":
    visitor = SoldierVisitor()
    visitor.visit_soldier("John")
```

Note that Python does not have direct equivalent of Java's `@Slf4j` annotation. The logging module in Python is used to log messages and it can be configured to output logs at different levels (DEBUG, INFO, WARNING, ERROR).
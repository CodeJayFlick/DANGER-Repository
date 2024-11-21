Here is the translation of the given Java code into Python:

```Python
import logging

class ConfigureForUnixVisitor:
    def visit(self, zoom):
        logging.info(f"{zoom} used with Unix configurator.")

if __name__ == "__main__":
    # Example usage
    visitor = ConfigureForUnixVisitor()
    zoom = "Some Zoom"
    visitor.visit(zoom)
```

Please note that Python does not have direct equivalent of Java's `@Slf4j` annotation. The logging module in Python is used to log messages, but it needs to be configured separately. In this example, I've assumed the logging configuration for simplicity and directly called the logger from within the class method.
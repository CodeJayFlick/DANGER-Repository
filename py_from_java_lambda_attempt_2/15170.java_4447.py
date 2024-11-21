Here is the translation of the Java code to Python:
```
import logging

class SergeantVisitor:
    def visit_soldier(self, soldier):
        # Do nothing
        pass

    def visit_sergeant(self, sergeant):
        logging.info("Hello {}".format(sergeant))

    def visit_commander(self, commander):
        # Do nothing
        pass


if __name__ == "__main__":
    SERGEANT_VISITOR = SergeantVisitor()
```
Note that I've removed the `@Slf4j` annotation and replaced it with a simple import of the logging module. In Python, we don't need to annotate classes or methods with special markers like Java does.

Also, in Python, we use indentation instead of curly braces `{}` to define code blocks (e.g., functions).
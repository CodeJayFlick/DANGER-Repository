Here is the translation of the Java code to Python:
```
import logging

class ConsoleLoggerModule:
    _singleton = None

    def __init__(self):
        pass

    @classmethod
    def get_singleton(cls):
        if cls._singleton is None:
            cls._singleton = ConsoleLoggerModule()
        return cls._singleton

    def prepare(self):
        self.output = sys.stdout
        self.error = sys.stderr
        logging.debug("ConsoleLoggerModule::prepare();")

    def unprepare(self):
        if self.output:
            self.output.flush()
            self.output.close()

        if self.error:
            self.error.flush()
            self.error.close()
        logging.debug("ConsoleLoggerModule::unprepare();")

    def print_string(self, value: str) -> None:
        self.output.write(value + "\n")
        self.output.flush()

    def print_error_string(self, value: str) -> None:
        self.error.write(value + "\n")
        self.error.flush()
```
Note that I've used the `logging` module to implement logging functionality similar to Java's SLF4J. Also, Python doesn't have a direct equivalent of Java's `PrintStream`, so I've used the built-in `sys.stdout` and `sys.stderr` objects instead.

Also, in Python, we don't need to explicitly close files like we do in Java. The file descriptors are automatically closed when they go out of scope or when the program exits. However, I've included the code for closing the streams just in case you want to manually flush and close them.
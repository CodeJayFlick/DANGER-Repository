Here is the translation of the Java code into Python:

```Python
import logging
import os

class FileLoggerModule:
    _singleton = None

    OUTPUT_FILE = "output.txt"
    ERROR_FILE = "error.txt"

    def __init__(self):
        pass

    @classmethod
    def get_singleton(cls):
        if cls._singleton is None:
            cls._singleton = cls()
        return cls._singleton

    def prepare(self):
        logging.debug("FileLoggerModule::prepare();")

        try:
            self.output_file = open(OUTPUT_FILE, 'w')
            self.error_file = open(ERROR_FILE, 'w')
        except FileNotFoundError as e:
            raise e
        finally:
            if hasattr(self, 'output_file'):
                self.output_file.close()
            if hasattr(self, 'error_file'):
                self.error_file.close()

    def unprepare(self):
        logging.debug("FileLoggerModule::unprepare();")

        if hasattr(self, 'output_file') and self.output_file is not None:
            self.output_file.flush()
            self.output_file.close()

        if hasattr(self, 'error_file') and self.error_file is not None:
            self.error_file.flush()
            self.error_file.close()

    def print_string(self, value):
        logging.info(value)

    def print_error_string(self, value):
        logging.error(value)
```

Please note that Python does not have a direct equivalent to Java's `PrintStream` class. The above code uses the built-in `logging` module for printing messages and files are handled using the `open()` function in read-write mode (`'w'`).
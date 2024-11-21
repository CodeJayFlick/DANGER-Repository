Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from logging import getLogger, INFO

class ConfigureForUnixVisitorTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.logger = getLogger(__name__)

    def tearDown(self):
        pass  # Clear loggers here if needed

    def test_visit_for_zoom(self):
        con_unix = ConfigureForUnixVisitor()
        zoom = Zoom()

        con_unix.visit(zoom)

        self.assertEqual(
            [event for event in self.logger.records],
            [{"levelno": INFO, "message": f"{zoom} used with Unix configurator."}]
        )

if __name__ == "__main__":
    unittest.main()
```

Note that Python's logging module does not have a direct equivalent to Java's SLF4J. The above code uses the built-in `logging` module for logging purposes.

Also, note that there is no direct translation of Java's static imports into Python. In this case, I've avoided using any external libraries or modules and instead used the standard library's `unittest` framework for testing.
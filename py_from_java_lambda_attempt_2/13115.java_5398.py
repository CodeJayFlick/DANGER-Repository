Here is the translation of the given Java code into equivalent Python:

```Python
import unittest

class ARM10e_O0_EmulatorTest:
    LANGUAGE_ID = "ARM:LE:32:v8"
    COMPILER_SPEC_ID = "default"

    REG_DUMP_SET = []

    def __init__(self, name):
        super().__init__(name, self.LANGUAGE_ID, self.COMPILER_SPEC_ID, self.REG_DUMP_SET)

    @property
    def processor_designator(self):
        return "ARM10e_GCC_O0"

    @classmethod
    def suite(cls):
        from unittest import TestSuite

        test_suite = TestSuite()
        test_suite.addTest(unittest.makeSuite(ARM10e_O0_EmulatorTest))
        return test_suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    runner.run(ARM10e_O0_EmulatorTest.suite())
```

Please note that Python does not have direct equivalent of Java's `@Override` annotation. In the given code, I've used a property decorator (`@property`) to achieve similar functionality for the `processor_designator` method.

Also, in order to run this test suite as a standalone script (like you would do with JUnit tests), we need to use Python's built-in unittest module and its TextTestRunner.
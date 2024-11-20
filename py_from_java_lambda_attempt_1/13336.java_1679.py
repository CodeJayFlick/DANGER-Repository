Here is the translation of the given Java code into equivalent Python:

```Python
import unittest

class PIC30_O0_EmulatorTest:
    LANGUAGE_ID = "dsPIC30F:LE:24:default"
    COMPILER_SPEC_ID = "default"

    REG_DUMP_SET = []

    def __init__(self, name):
        super().__init__(name, self.LANGUAGE_ID, self.COMPILER_SPEC_ID, self.REG_DUMP_SET)

    @property
    def processor_designator(self):
        return "PIC30_ GCC_O0"

    @property
    def preferred_stack_symbol_name(self):
        return "__SP_init"

class TestSuite(unittest.TestCase):

    @classmethod
    def suite(cls):
        return unittest.makeSuite(PIC30_O0_EmulatorTest)

if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    test_suite = PIC30_O0_EmulatorTest.suite()
    runner.run(test_suite)
```

Please note that Python does not have direct equivalent of Java's package, import statements or annotations. Also, the concept of static methods and variables is different in Python compared to Java.
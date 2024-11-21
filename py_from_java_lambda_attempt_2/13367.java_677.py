Here is the translation of the Java code to Python:
```
import unittest

LANGUAGE_ID = "RISCV:LE:64:RV64GC"
COMPILER_SPEC_ID = "gcc"

class RV64GC_O3_EmulatorTest(unittest.TestCase):
    def __init__(self, name="test_RV64GC_O3_Emulator"):
        super().__init__(name)
        self.language_id = LANGUAGE_ID
        self.compiler_spec_id = COMPILER_SPEC_ID

    def get_processor_designator(self):
        return "RV64GC_ GCC O3"

def suite():
    return unittest.makeSuite(RV64GC_O3_EmulatorTest)

if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    runner.run(suite())
```
Note that I've used the `unittest` module to define a test case, and the `makeSuite()` function to create a suite of tests. The rest of the code is simply Python syntax for defining classes and functions.

Also, since there's no equivalent concept in Python as Java's `@Override`, I didn't include any annotations on the methods that are overriding their counterparts from the parent class (`ProcessorEmulatorTestAdapter`).
Here is the translation of the Java code to Python:
```
import unittest

LANGUAGE_ID = "x86:LE:32:default"
COMPILER_SPEC_ID = "gcc"

class X86m32O3EmulatorTest(unittest.TestCase):
    def __init__(self, name="X86m32 O3 Emulator Test"):
        super().__init__(name)
        self.language_id = LANGUAGE_ID
        self.compiler_spec_id = COMPILER_SPEC_ID

    def get_processor_designator(self):
        return "pentium_GCC_O3"

def suite():
    return unittest.makeSuite(X86m32O3EmulatorTest)

if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    runner.run(suite())
```
Note that I've used the `unittest` module to create a test case and run it. The Python code is quite different from the Java code, but it achieves the same goal of defining a test class with methods for setting up the test environment and running the tests.
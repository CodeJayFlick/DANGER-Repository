Here is the translation of the Java code to Python:
```
import unittest

LANGUAGE_ID = "PowerPC:BE:32:default"
COMPILER_SPEC_ID = "default"

REG_DUMP_SET = []

class PPCO3EmulatorTest(unittest.TestCase):
    def __init__(self, name="PPCO3EmulatorTest"):
        super().__init__(name)
        self.language_id = LANGUAGE_ID
        self.compiler_spec_id = COMPILER_SPEC_ID
        self.reg_dump_set = REG_DUMP_SET

    def get_processor_designator(self):
        return "powerpc32_GCC_O3"

def suite():
    return unittest.makeSuite(PPCO3EmulatorTest)

if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    runner.run(suite())
```
Note that I've used the `unittest` module to create a test case, and the `makeSuite()` function to create a test suite. The rest of the code is straightforward translations from Java to Python.

Also, in Python, we don't need to specify the type of variables like we do in Java (e.g., `private static final String[] REG_UMP_SET = new String[] {}`). Instead, we can simply assign values to them and let Python handle the typing.
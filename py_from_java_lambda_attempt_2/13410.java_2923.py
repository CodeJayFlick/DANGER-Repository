Here is the translation of the Java code to Python:
```
import unittest

class X86m64_O3_EmulatorTest(unittest.TestCase):
    LANGUAGE_ID = "x86:LE:64:default"
    COMPILER_SPEC_ID = "gcc"

    REG_DUMP_SET = []

    def __init__(self, name="X86m64_ O3_EmulatorTest"):
        super().__init__(name)
        self.language_id = X86m64_O3_EmulatorTest.LANGUAGE_ID
        self.compiler_spec_id = X86m64_O3_EmulatorTest.COMPILER_SPEC_ID
        self.reg_dump_set = X86m64_O3_EmulatorTest.REG_DUMP_SET

    def get_processor_designator(self):
        return "x86_m64_GCC_O3"

    @classmethod
    def suite(cls):
        return unittest.makeSuite(X86m64_O3_EmulatorTest)

if __name__ == "__main__":
    unittest.main()
```
Note that I've used the `unittest` module to create a test case, and replaced the Java-specific constructs (e.g. `package`, `public class`, etc.) with Python's equivalent syntax.
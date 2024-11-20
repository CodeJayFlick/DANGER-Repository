Here is the translation of the given Java code into equivalent Python:

```Python
import unittest

class RV32GC_O3_EmulatorTest(unittest.TestCase):
    LANGUAGE_ID = "RISCV:LE:32:RV32GC"
    COMPILER_SPEC_ID = "gcc"

    def __init__(self, name="test_RV32GC_O3_Emulator"):
        super().__init__(name)
        self.reg_dump_set = []

    def get_processor_designator(self):
        return "RV32GC_ GCC O3"

    @classmethod
    def suite(cls):
        return unittest.makeSuite(RV32GC_O3_EmulatorTest)

if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    runner.run(unittest.makeSuite(RV32GC_O3_EmulatorTest))
```

Note that Python does not have direct equivalent of Java's `package`, so I did not include it in the translation. Also, Python uses a different syntax for classes and methods compared to Java.
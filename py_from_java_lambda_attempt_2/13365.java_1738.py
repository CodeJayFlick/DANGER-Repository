Here is the equivalent Python code:

```Python
import unittest

class RV32IMC_O0_EmulatorTest(unittest.TestCase):
    LANGUAGE_ID = "RISCV:LE:32:RV32IMC"
    COMPILER_SPEC_ID = "gcc"

    def __init__(self, name="test_RV32IMC_O0_Emulator"):
        super().__init__(name)
        self.reg_dump_set = []

    def get_processor_designator(self):
        return "RV32IMC_ GCC O0"


def suite():
    return unittest.makeSuite(RV32IMC_O0_EmulatorTest)


if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    test_suite = suite()
    runner.run(test_suite)
```

Note that Python does not have direct equivalents for Java's `package`, `public class`, and other constructs. The equivalent code is written in a more object-oriented style, using classes and methods to define the structure of your program.
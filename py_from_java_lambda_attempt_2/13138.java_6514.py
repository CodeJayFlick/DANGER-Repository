Here is a translation of the given Java code into equivalent Python:

```Python
import unittest

class AVR86CCOOEmulatorTest:
    LANGUAGE_ID = "avr8:LE:16:atmega256"
    COMPILER_SPEC_ID = "gcc"

    REG_DUMP_SET = []

    def __init__(self, name):
        super().__init__(name, self.LANGUAGE_ID, self.COMPILER_SPEC_ID, self.REG_DUMP_SET)

    @property
    def processor_designator(self):
        return "AVR8_6_GCC_O0"

    def initialize_state(self, test_runner, program):
        # These eliminate  "uninitialized register" errors. Not strictly needed, but helps find actual problems.
        test_runner.set_register("SP", 0x0)
        test_runner.set_register("R1", 0x0)
        test_runner.set_register("Y", 0x0)
        test_runner.set_register("W", 0x0)

    def set_analysis_options(self, analysis_options):
        super().set_analysis_options(analysis_options)
        analysis_options.set_boolean("Reference", False)  # too many bad disassemblies
        analysis_options.set_boolean("Data Reference", False)


class TestSuite(unittest.TestCase):

    @classmethod
    def suite(cls):
        return unittest.makeSuite(AVR86CCOOEmulatorTest, "AVR8_6_GCC_O0_Emulator_Test")


if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    test_suite = AVR86CCOOEmulatorTest.suite()
    runner.run(test_suite)
```

Please note that Python does not have direct equivalent of Java's `@Override` annotation.
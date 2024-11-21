Here is a translation of the provided Java code into equivalent Python:

```Python
import unittest

class AVR851GCCO0EmulatorTest:
    LANGUAGE_ID = "avr8:LE:16:extended"
    COMPILER_SPEC_ID = "gcc"

    REG_DUMP_SET = []

    def __init__(self, name):
        super().__init__(name, self.LANGUAGE_ID, self.COMPILER_SPEC_ID, self.REG_DUMP_SET)

    @property
    def processor_designator(self):
        return "AVR8_51_GCC_O0"

    def initialize_state(self, test_runner, program):
        # These eliminate  "uninitialized register" errors. Not strictly needed, but helps find actual problems.
        test_runner.set_register("SP", 0x0)
        test_runner.set_register("R1", 0x0)
        test_runner.set_register("Y", 0x0)
        test_runner.set_register("W", 0x0)

    def set_analysis_options(self, analysis_options):
        super().set_analysis_options(analysis_options)
        analysis_options["Reference"] = False
        # too many bad disassemblies

class TestSuite(unittest.TestCase):

    @classmethod
    def suite(cls):
        return unittest.makeSuite(AVR851GCCO0EmulatorTest)

if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    test_suite = AVR851GCCO0EmulatorTest.suite()
    runner.run(test_suite)
```

Please note that Python does not have direct equivalent of Java's `@Override` annotation. The method overriding is done by using the same name and signature as in parent class.

Also, Python doesn't support static methods like Java. So I removed them from your code.
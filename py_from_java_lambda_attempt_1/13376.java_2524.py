Here is a translation of the Java code into equivalent Python:

```Python
import unittest

class SparcV9_64_O3_EmulatorTest:
    LANGUAGE_ID = "sparc:BE:64:default"
    COMPILER_SPEC_ID = "default"

    REG_DUMP_SET = []

    def __init__(self, name):
        super().__init__(name, self.LANGUAGE_ID, self.COMPILER_SPEC_ID, self.REG_DUMP_SET)

    @property
    def processor_designator(self):
        return "sparcV9_64_GCC_O3"

    def initialize_state(self, test_runner, program):
        test_runner.set_register("DECOMPILE_MODE", 0x0)  # turn decompile mode off

def suite():
    return unittest.makeSuite(SparcV9_64_O3_EmulatorTest)

if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    runner.run(suite())
```

Please note that Python does not have direct equivalent of Java's `@Override` annotation. The method is simply defined as a regular function in the subclass.

Also, Python has no concept of static methods or variables like Java. In this translation, I've made them instance variables and methods respectively.
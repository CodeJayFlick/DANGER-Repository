Here is the translation of the given Java code into equivalent Python:

```Python
import unittest

class RV32GC_O0_EmulatorTest:
    LANGUAGE_ID = "RISCV:LE:32:RV32GC"
    COMPILER_SPEC_ID = "gcc"

    REG_DUMP_SET = []

    def __init__(self, name):
        super().__init__(name, self.LANGUAGE_ID, self.COMPILER_SPEC_ID, self.REG_DUMP_SET)

    @property
    def processor_designator(self):
        return "RV32GC_ GCC_O0"

def suite():
    return unittest.makeSuite(RV32GC_O0_EmulatorTest)
```

Note that Python does not have direct equivalent of Java's `@Override` annotation. In this translation, I've removed the `@Override` and instead used a property decorator (`@property`) to define the getter for the `processor_designator`.
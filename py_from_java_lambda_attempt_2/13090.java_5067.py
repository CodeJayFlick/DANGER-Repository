Here is the translation of the given Java code into equivalent Python:

```Python
import unittest

class M68000O0EmulatorTest:
    LANGUAGE_ID = "68000:BE:32:default"
    COMPILER_SPEC_ID = "default"

    REG_DUMP_SET = []

    def __init__(self, name):
        super().__init__(name, self.LANGUAGE_ID, self.COMPILER_SPEC_ID, self.REG_DUMP_SET)

    @property
    def processor_designator(self):
        return "m68000_GCC_O0"


def suite():
    return unittest.makeSuite(M68000O0EmulatorTest)


if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    test_suite = suite()
    runner.run(test_suite)
```

Note that Python does not have direct equivalent of Java's `@Override` annotation. In the given code, I've used a property decorator (`@property`) to define the getter for the `processor_designator`.
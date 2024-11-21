Here is the translation of the given Java code into Python:

```Python
import unittest

class MIPS16MIX_O3_EmulatorTest:
    LANGUAGE_ID = "MIPS:BE:32:default"
    COMPILER_SPEC_ID = "default"

    REG_DUMP_SET = []

    def __init__(self, name):
        super().__init__(name, self.LANGUAGE_ID, self.COMPILER_SPEC_ID, self.REG_DUMP_SET)

    @property
    def processor_designator(self):
        return "MIPS16MIX_ GCC_O3"

    @classmethod
    def suite(cls):
        return unittest.makeSuite(MIPS16MIX_O3_EmulatorTest)


if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    runner.run(unittest.makeSuite(MIPS16MIX_O3_EmulatorTest))
```

Please note that Python does not have direct equivalent of Java's `@Override` annotation. The method overriding is done by using the same name as in parent class and it will automatically override if a method with the same name exists in parent class.

Also, there are some differences between Python and Java syntax. For example, in Python we don't need to specify types for variables or function parameters unless they're necessary (like when you want to use a variable that can hold any type of value).
Here is the translation of the given Java code into equivalent Python:

```Python
import unittest

class ARM10e_O3_EmulatorTest:
    LANGUAGE_ID = "ARM:LE:32:v8"
    COMPILER_SPEC_ID = "default"

    REG_DUMP_SET = []

    def __init__(self, name):
        super().__init__(name, self.LANGUAGE_ID, self.COMPILER_SPEC_ID, self.REG_DUMP_SET)

    @property
    def processor_designator(self):
        return "ARM10e_GCC_O3"

def suite():
    return unittest.makeSuite(ARM10e_O3_EmulatorTest)
```

Please note that Python does not have direct equivalent of Java's `@Override` annotation. The `processor_designator` method is defined as a property in the above code, which serves similar purpose to the overridden method in Java.
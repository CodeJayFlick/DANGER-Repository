Here is the equivalent Python code:

```Python
import unittest

class ARM_O3_EmulatorTest:
    LANGUAGE_ID = "ARM:LE:32:v8"
    COMPILER_SPEC_ID = "default"

    REG_DUMP_SET = []

    def __init__(self, name):
        super().__init__(name, self.LANGUAGE_ID, self.COMPILER_SPEC_ID, self.REG_DUMP_SET)

    @property
    def processor_designator(self):
        return "ARM_GCC_O3"

def suite():
    return unittest.makeSuite(ARM_O3_EmulatorTest)
```

Note that Python does not have direct equivalents for Java's `package`, `public class`, and other keywords. The code is structured as a single module with classes, functions, and variables defined within it.

The `ProcessorEmulatorTestAdapter` in the original Java code seems to be related to testing frameworks or adapters, which are typically handled by Python's built-in `unittest` framework.
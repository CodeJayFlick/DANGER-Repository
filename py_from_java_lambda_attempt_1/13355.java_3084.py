Here is the equivalent Python code:

```Python
import unittest

class PPCP9Alt_O3_EmulatorTest(unittest.TestCase):
    LANGUAGE_ID = "PowerPC:BE:64:A2ALT-32addr"
    COMPILER_SPEC_ID = "default"

    REG_DUMP_SET = []

    def __init__(self, name="test_PPCP9Alt_O3_Emulator"):
        super().__init__(name)
        self.language_id = PPCP9Alt_O3_EmulatorTest.LANGUAGE_ID
        self.compiler_spec_id = PPCP9Alt_O3_EmulatorTest.COMPILER_SPEC_ID
        self.reg_dump_set = PPCP9Alt_O3_EmulatorTest.REG_DUMP_SET

    def get_processor_designator(self):
        return "ppcP9Alt_GCC_O3"

    @classmethod
    def suite(cls):
        return unittest.makeSuite(PPCP9Alt_O3_EmulatorTest, 'test_PPCP9Alt_O3_Emulator')

if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    runner.run(unittest.makeSuite(PPCP9Alt_O3_EmulatorTest))
```

Note that Python does not have direct equivalent of Java's `package` statement. Also, the concept of static variables and methods is different in Python compared to Java.
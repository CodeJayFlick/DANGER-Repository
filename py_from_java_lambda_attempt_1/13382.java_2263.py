Here is the equivalent Python code:

```Python
import unittest

class SuperH4_BE_O0_EmulatorTest(unittest.TestCase):

    LANGUAGE_ID = "SuperH4:BE:32:default"
    COMPILER_SPEC_ID = "default"

    REG_DUMP_SET = []

    def __init__(self, name):
        super().__init__(name)
        self.language_id = self.LANGUAGE_ID
        self.compiler_spec_id = self.COMPILER_SPEC_ID
        self.reg_dump_set = self.REG_DUMP_SET

    def get_processor_designator(self):
        return "SH4_ GCC_O0"

    @classmethod
    def suite(cls):
        return unittest.makeSuite(SuperH4_BE_O0_EmulatorTest, 'SuperH4_BE_O0_EmulatorTest')

if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    runner.run(unittest.makeSuite(SuperH4_BE_O0_EmulatorTest))
```

Note that Python does not have direct equivalent of Java's `package`, so I removed the package declaration. Also, Python uses indentation to denote block-level structure, which is different from Java's use of curly braces and keywords like `public` or `private`.
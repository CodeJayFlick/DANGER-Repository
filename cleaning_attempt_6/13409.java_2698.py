import unittest

class X86m64_O0_EmulatorTest(unittest.TestCase):
    LANGUAGE_ID = "x86:LE:64:default"
    COMPILER_SPEC_ID = "gcc"

    REG_DUMP_SET = []

    def __init__(self, name="X86m64_O0_EmulatorTest"):
        super().__init__(name)
        self.language_id = X86m64_O0_EmulatorTest.LANGUAGE_ID
        self.compiler_spec_id = X86m64_O0_EmulatorTest.COMPILER_SPEC_ID

    def get_processor_designator(self):
        return "x86_64_GCC_O0"

    @classmethod
    def suite(cls):
        return unittest.makeSuite(X86m64_O0_EmulatorTest, 'X86m64_O0_EmulatorTest')

if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    runner.run(unittest.makeSuite(X86m64_O0_EmulatorTest))

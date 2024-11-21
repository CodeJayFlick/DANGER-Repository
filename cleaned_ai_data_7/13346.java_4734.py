import unittest

class PPC64_O0_EmulatorTest(unittest.TestCase):
    LANGUAGE_ID = "PowerPC:BE:64:default"
    COMPILER_SPEC_ID = "default"

    REG_DUMP_SET = []

    def __init__(self, name="test"):
        super().__init__(name)
        self.language_id = PPC64_O0_EmulatorTest.LANGUAGE_ID
        self.compiler_spec_id = PPC64_O0_EmulatorTest.COMPILER_SPEC_ID
        self.reg_dump_set = PPC64_O0_EmulatorTest.REG_DUMP_SET

    def get_processor_designator(self):
        return "powerpc64_GCC_O0"

    @classmethod
    def suite(cls):
        return unittest.makeSuite(PPC64_O0_EmulatorTest, 'test')

if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    runner.run(unittest.makeSuite(PPC64_O0_EmulatorTest))

import unittest

class MIPS16_O0_EmulatorTest(unittest.TestCase):

    LANGUAGE_ID = "MIPS:BE:32:default"
    COMPILER_SPEC_ID = "default"

    REG_DUMP_SET = []

    def __init__(self, name):
        super().__init__(name)
        self.language_id = self.LANGUAGE_ID
        self.compiler_spec_id = self.COMPILER_SPEC_ID
        self.reg_dump_set = self.REG_DUMP_SET

    def get_processor_designator(self):
        return "MIPS16_ GCC_O0"

    @classmethod
    def suite(cls):
        return unittest.makeSuite(MIPS16_O0_EmulatorTest, 'test')

if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    runner.run(unittest.makeSuite(MIPS16_O0_EmulatorTest, 'test'))

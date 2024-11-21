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

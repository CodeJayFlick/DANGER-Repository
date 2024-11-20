import unittest

class MIPSEL_O3_EmulatorTest:
    LANGUAGE_ID = "MIPS:LE:32:default"
    COMPILER_SPEC_ID = "default"

    REG_DUMP_SET = []

    def __init__(self, name):
        super().__init__(name, self.LANGUAGE_ID, self.COMPILER_SPEC_ID, self.REG_DUMP_SET)

    @property
    def processor_designator(self):
        return "MIPSEL_ GCC_O3"

def suite():
    return unittest.makeSuite(MIPSEL_O3_EmulatorTest)

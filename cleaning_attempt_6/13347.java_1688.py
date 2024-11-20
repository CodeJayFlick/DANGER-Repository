import unittest

class PPC64_O3_EmulatorTest:
    LANGUAGE_ID = "PowerPC:BE:64:default"
    COMPILER_SPEC_ID = "default"

    REG_DUMP_SET = []

    def __init__(self, name):
        super().__init__(name, self.LANGUAGE_ID, self.COMPILER_SPEC_ID, self.REG_DUMP_SET)

    @property
    def processor_designator(self):
        return "powerpc64_GCC_O3"

def suite():
    return unittest.makeSuite(PPC64_O3_EmulatorTest)

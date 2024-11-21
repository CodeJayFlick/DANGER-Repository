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

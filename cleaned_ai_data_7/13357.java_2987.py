import unittest

LANGUAGE_ID = "PowerPC:BE:32:default"
COMPILER_SPEC_ID = "default"

REG_DUMP_SET = []

class PPCO3EmulatorTest(unittest.TestCase):
    def __init__(self, name="PPCO3EmulatorTest"):
        super().__init__(name)
        self.language_id = LANGUAGE_ID
        self.compiler_spec_id = COMPILER_SPEC_ID
        self.reg_dump_set = REG_DUMP_SET

    def get_processor_designator(self):
        return "powerpc32_GCC_O3"

def suite():
    return unittest.makeSuite(PPCO3EmulatorTest)

if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    runner.run(suite())

import unittest

LANGUAGE_ID = "MIPS:BE:64:64-32addr"
COMPILER_SPEC_ID = "default"

class MIPS64_32addr_O0_EmulatorTest(unittest.TestCase):
    def __init__(self, name="test_MIPS64_32addr_O0_Emulator"):
        super().__init__(name)
        self.language_id = LANGUAGE_ID
        self.compiler_spec_id = COMPILER_SPEC_ID

    def get_processor_designator(self):
        return "MIPS64_32addr_GCC_O0"

def suite():
    return unittest.makeSuite(MIPS64_32addr_O0_EmulatorTest)

if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    runner.run(suite())

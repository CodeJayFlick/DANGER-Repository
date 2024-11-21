import unittest

LANGUAGE_ID = "RISCV:LE:64:RV64GC"
COMPILER_SPEC_ID = "gcc"

class RV64GC_O3_EmulatorTest(unittest.TestCase):
    def __init__(self, name="test_RV64GC_O3_Emulator"):
        super().__init__(name)
        self.language_id = LANGUAGE_ID
        self.compiler_spec_id = COMPILER_SPEC_ID

    def get_processor_designator(self):
        return "RV64GC_ GCC O3"

def suite():
    return unittest.makeSuite(RV64GC_O3_EmulatorTest)

if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    runner.run(suite())

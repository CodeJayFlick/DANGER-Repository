import unittest

class RV64GO3EmulatorTest(unittest.TestCase):
    LANGUAGE_ID = "RISCV:LE:64:RV64G"
    COMPILER_SPEC_ID = "gcc"

    def __init__(self, name="test_RV64_GO_3_Emulator"):
        super().__init__(name)
        self.reg_dump_set = []

    def get_processor_designator(self):
        return "RV64G_GCC_O3"


if __name__ == "__main__":
    suite = unittest.makeSuite(RV64GO3EmulatorTest, 'test')

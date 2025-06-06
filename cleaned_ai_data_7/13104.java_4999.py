import unittest

class AARCH64_O3_EmulatorTest(unittest.TestCase):
    LANGUAGE_ID = "AARCH64:LE:64:v8A"
    COMPILER_SPEC_ID = "default"

    REG_DUMP_SET = []

    def __init__(self, name="test_AARCH64_O3_Emulator"):
        super().__init__(name)
        self.language_id = AARCH64_O3_EmulatorTest.LANGUAGE_ID
        self.compiler_spec_id = AARCH64_O3_EmulatorTest.COMPILER_SPEC_ID
        self.reg_dump_set = AARCH64_O3_EmulatorTest.REG_DUMP_SET

    def get_processor_designator(self):
        return "AARCH64_GCC_O3"

    @classmethod
    def suite(cls):
        return unittest.makeSuite(AARCH64_O3_EmulatorTest)

if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    runner.run(unittest.makeSuite(AARCH64_O3_EmulatorTest))

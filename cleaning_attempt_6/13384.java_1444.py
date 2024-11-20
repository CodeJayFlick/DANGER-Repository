import unittest

class SuperH4_O0_EmulatorTest(unittest.TestCase):

    LANGUAGE_ID = "SuperH4:LE:32:default"
    COMPILER_SPEC_ID = "default"

    REG_DUMP_SET = []

    def __init__(self, name):
        super().__init__(name)
        self.language_id = self.LANGUAGE_ID
        self.compiler_spec_id = self.COMPILER_SPEC_ID
        self.reg_dump_set = self.REG_DUMP_SET

    def get_processor_designator(self):
        return "SH4_LE_GCC_O0"

    @classmethod
    def suite(cls):
        return unittest.makeSuite(SuperH4_O0_EmulatorTest)

if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    runner.run(unittest.makeSuite(SuperH4_O0_EmulatorTest))

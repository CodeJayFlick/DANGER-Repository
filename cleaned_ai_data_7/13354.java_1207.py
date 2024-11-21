import unittest

class PPCP9Alt_O0_EmulatorTest(unittest.TestCase):

    LANGUAGE_ID = "PowerPC:BE:64:A2ALT-32addr"
    COMPILER_SPEC_ID = "default"

    REG_DUMP_SET = []

    def __init__(self, name):
        super().__init__(name)
        self.language_id = PPCP9Alt_O0_EmulatorTest.LANGUAGE_ID
        self.compiler_spec_id = PPCP9Alt_O0_EmulatorTest.COMPILER_SPEC_ID

    def get_processor_designator(self):
        return "ppcP9Alt_GCC_O0"

    @classmethod
    def suite(cls):
        return unittest.makeSuite(PPCP9Alt_O0_EmulatorTest)


if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    runner.run(unittest.makeSuite(PPCP9Alt_O0_EmulatorTest))

import unittest

class MIPS64R6_O3_EmulatorTest:
    LANGUAGE_ID = "MIPS:BE:64:R6"
    COMPILER_SPEC_ID = "default"

    REG_DUMP_SET = []

    def __init__(self, name):
        super().__init__(name, self.LANGUAGE_ID, self.COMPILER_SPEC_ID, self.REG_DUMP_SET)

    @property
    def processor_designator(self):
        return "MIPS64R6_ GCC_O3"


def suite():
    return unittest.makeSuite(MIPS64R6_O3_EmulatorTest)


if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    test_suite = MIPS64R6_O3_EmulatorTest("test_name")
    runner.run(test_suite)

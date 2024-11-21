import unittest

class TRICORE_BE_O3_EmulatorTest:
    LANGUAGE_ID = "tricore:LE:32:default"
    COMPILER_SPEC_ID = "default"

    REG_DUMP_SET = []

    def __init__(self, name):
        super().__init__(name, self.LANGUAGE_ID, self.COMPILER_SPEC_ID, self.REG_DUMP_SET)

    @property
    def processor_designator(self):
        return "tricore_GCC_O3"

    def initialize_state(self, test_runner, program):
        test_runner.set_register("a10", 0x40000000)
        test_runner.set_register("FCX", 0x20000)
        test_runner.set_register("LCX", 0x30000)
        test_runner.set_register("PCXI", 0)

    def set_analysis_options(self, analysis_options):
        super().set_analysis_options(analysis_options)
        analysis_options["Reference"] = False

    @classmethod
    def suite(cls):
        return unittest.makeSuite(TRICORE_BE_O3_EmulatorTest)


if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    test_suite = TRICORE_BE_O3_EmulatorTest.suite()
    runner.run(test_suite)

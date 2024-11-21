import unittest

class AVR8_xmega_GCC_O0_EmulatorTest(unittest.TestCase):

    LANGUAGE_ID = "avr8:LE:24:xmega"
    COMPILER_SPEC_ID = "gcc"

    REG_DUMP_SET = []

    def __init__(self, name):
        super().__init__(name)
        self.language_id = self.LANGUAGE_ID
        self.compiler_spec_id = self.COMPILER_SPEC_ID

    def get_processor_designator(self):
        return "AVR8_xmega_GCC_O0"

    def initialize_state(self, test_runner, program):
        # These eliminate  "uninitialized register" errors. Not strictly needed, but helps find actual problems.
        test_runner.set_register("SP", 0x0)
        test_runner.set_register("R1", 0x0)
        test_runner.set_register("Y", 0x0)
        test_runner.set_register("W", 0x0)

    def set_analysis_options(self, analysis_options):
        super().set_analysis_options(analysis_options)
        analysis_options["Reference"] = False
        analysis_options["Data Reference"] = False

    @classmethod
    def suite(cls):
        return unittest.makeSuite(AVR8_xmega_GCC_O0_EmulatorTest)

if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    runner.run(unittest.makeSuite(AVR8_xmega_GCC_O0_EmulatorTest))

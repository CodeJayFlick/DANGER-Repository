import unittest

class SparcV9_64_O0_EmulatorTest(unittest.TestCase):

    LANGUAGE_ID = "sparc:BE:64:default"
    COMPILER_SPEC_ID = "default"

    REG_DUMP_SET = []

    def __init__(self, name):
        super().__init__(name)
        self.language_id = self.LANGUAGE_ID
        self.compiler_spec_id = self.COMPILER_SPEC_ID

    def get_processor_designator(self):
        return "sparcV9_64_GCC_O0"

    def initialize_state(self, test_runner, program):
        test_runner.set_register("DECOMPILE_MODE", 0x0)  # turn decompile mode off


if __name__ == "__main__":
    suite = unittest.makeSuite(SparcV9_64_O0_EmulatorTest)

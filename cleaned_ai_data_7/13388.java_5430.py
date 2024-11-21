class TRICORE_BE_O0_EmulatorTest:
    LANGUAGE_ID = "tricore:LE:32:default"
    COMPILER_SPEC_ID = "default"
    REG_DUMP_SET = []

    def __init__(self, name):
        super().__init__(name, self.LANGUAGE_ID, self.COMPILER_SPEC_ID, self.REG_DUMP_SET)

    @property
    def processor_designator(self):
        return "tricore_GCC_O0"

    def initialize_state(self, test_runner, program):
        test_runner.set_register("a10", 0x40000000)
        test_runner.set_register("FCX", 0x20000)
        test_runner.set_register("LCX", 0x30000)
        test_runner.set_register("PCXI", 0)

    @classmethod
    def suite(cls):
        return cls.build_emulator_test_suite(cls)

    def set_analysis_options(self, analysis_options):
        super().set_analysis_options(analysis_options)
        analysis_options.set_boolean("Reference", False)


# Usage:
test = TRICORE_BE_O0_EmulatorTest("TRICORE BE O0 Emulator Test")

import unittest

class AVR32_BE_O3_EmulatorTest:
    LANGUAGE_ID = "avr32:BE:32:default"
    COMPILER_SPEC_ID = "default"

    REG_DUMP_SET = []

    def __init__(self, name):
        super().__init__(name, self.LANGUAGE_ID, self.COMPILER_SPEC_ID, self.REG_DUMP_SET)

    @property
    def processor_designator(self):
        return "AVR_ GCC_O3"

    def set_analysis_options(self, analysis_options):
        super().set_analysis_options(analysis_options)
        analysis_options["Reference"] = False  # too many bad disassemblies
        analysis_options["Data Reference"] = False  # too many bad disassemblies

    @classmethod
    def suite(cls):
        return unittest.makeSuite(AVR32_BE_O3_EmulatorTest)


if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    runner.run(unittest.makeSuite(AVR32_BE_O3_EmulatorTest))

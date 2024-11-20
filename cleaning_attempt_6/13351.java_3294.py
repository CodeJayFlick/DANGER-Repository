import unittest

LANGUAGE_ID = "PowerPC:BE:64:A2-32addr"
COMPILER_SPEC_ID = "default"

class PPCA2O3EmulatorTest(unittest.TestCase):
    def __init__(self, name="test"):
        super().__init__(name)
        self.language_id = LANGUAGE_ID
        self.compiler_spec_id = COMPILER_SPEC_ID

    def get_processor_designator(self):
        return "ppcA2_GCC_O3"

def suite():
    return unittest.makeSuite(PPCA2O3EmulatorTest)

if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    runner.run(suite())

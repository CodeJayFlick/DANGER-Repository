import unittest

LANGUAGE_ID = "x86:LE:32:default"
COMPILER_SPEC_ID = "gcc"

class X86m32O3EmulatorTest(unittest.TestCase):
    def __init__(self, name="X86m32 O3 Emulator Test"):
        super().__init__(name)
        self.language_id = LANGUAGE_ID
        self.compiler_spec_id = COMPILER_SPEC_ID

    def get_processor_designator(self):
        return "pentium_GCC_O3"

def suite():
    return unittest.makeSuite(X86m32O3EmulatorTest)

if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    runner.run(suite())

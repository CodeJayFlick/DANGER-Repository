import unittest
from ghidra.decompiler import DecompInterface
from ghidra.program.model.address import Address
from ghidra.program.model.listing import Function
from ghidra.program.model.listing import Program
from ghidra.test.ghidra_headed_integration_test import AbstractGhidraHeadedIntegrationTest

class DecompilerTest(AbstractGhidraHeadedIntegrationTest):
    def setUp(self):
        self.prog = ToyProgramBuilder("notepad_decompiler", True).create_memory("test", "0x0", 2)
        self.decompiler = DecompInterface()
        self.decompiler.open_program(self.prog)

    def tearDown(self):
        if self.decompiler:
            self.decompiler.dispose()

    @unittest.skip
    def testDecompileInterfaceReturnsAFunction(self):
        addr = Address(0x0, "test")
        func = self.prog.get_listing().get_function_at(addr)
        decomp_results = self.decompiler.decompile_function(func,
            DecompileOptions.SUGGESTED_DECOMPILE_TIMEOUT_SECS, TaskMonitor.DUMMY)
        decompilation = decomp_results.get_decompiled_function().getC()
        assert decompilation is not None

if __name__ == "__main__":
    unittest.main()

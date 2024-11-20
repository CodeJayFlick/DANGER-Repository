import unittest
from ghidra.dbg.target import TargetProcess
from ghidra.dbg.model.impl import GdbModelTargetInferior

class AbstractModelForGdbScenarioAmd64RegistersTest(unittest.TestCase):

    def get_specimen(self):
        return 'REGISTERS'

    def get_bin_module_name(self, specimen=None):
        if specimen is None:
            specimen = self.get_specimen()
        return specimen.get_command_line()

    def get_breakpoint_expression(self):
        return "*break_here"  # Don't decode prologue, GDB!

    def get_register_writes(self):
        register_writes = {}
        register_writes['rdi'] = bytes.fromhex('0000000000000041')
        return register_writes

    def verify_expected_effect(self, process: TargetProcess) -> None:
        status = process.get_typed_attribute_now_by_name(
            GdbModelTargetInferior.EXIT_CODE_ATTRIBUTE_NAME, int, 0
        )
        self.assertEqual(0x41, status)

if __name__ == '__main__':
    unittest.main()

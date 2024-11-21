import unittest
from ghidra_dbg import TargetProcess, DbgModelTargetProcessImpl

class AbstractModelForDbgengScenarioX64RegistersTest(unittest.TestCase):

    def get_specimen(self):
        return "WindowsSpecimen.REGISTERS"

    def get_breakpoint_expression(self):
        return "expRegisters!break_here"

    def get_register_writes(self):
        register_writes = {}
        register_writes["rcx"] = bytes.fromhex("0000000000000041")
        return register_writes

    def verify_expected_effect(self, process):
        status = process.get_attribute_now(DbgModelTargetProcessImpl.EXIT_CODE_ATTRIBUTE_NAME)
        self.assertTrue(status == 0x41 or status == 0)

if __name__ == "__main__":
    unittest.main()

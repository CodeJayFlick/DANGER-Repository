import unittest
from ghidra.program.database import ProgramDB
from ghidra.program.model.address import AddressSpace
from ghidra.program.model.lang import Language
from ghidra.program.model.mem import Memory
from ghidra.util.task import TaskMonitorAdapter

class ProgramContextTest(unittest.TestCase):

    def setUp(self):
        self.lang = get_sleigh_8051_language()
        self.space = lang.get_address_factory().get_default_address_space()

        program_db = ProgramDB("8051", lang, lang.get_default_compiler_spec(), None)
        self.program = program_db
        self.mem = program_db.get_memory()

    def test_register_name_lookup(self):
        program_context = self.program.get_program_context()
        for reg_name in program_context.get_register_names():
            reg = program_context.get_register(reg_name)
            assert reg is not None, f"Register {reg_name} not found"
            self.assertEqual(reg_name, reg.name)

    def test_all(self):
        id = self.program.start_transaction("Test")
        try:
            start_address = Address(0)
            mem.create_initialized_block("first", start_address, 100, bytes([0]), TaskMonitorAdapter.DUMMY_MONITOR, False)

            program_context = self.program.get_program_context()
            did_something = False

            for register in program_context.get_registers():
                if not register.is_base_register() and register.is_processor_context():
                    continue
                try:
                    program_context.set_value(register, start_address, Address(0x30), 255)
                except Exception as e:
                    self.fail(str(e))

                value = program_context.get_value(register, start_address, False)
                assert value is not None

            did_something = True
        finally:
            self.program.end_transaction(id, False)

    def test_get_register(self):
        register = self.program.get_program_context().get_register("register_name")
        self.assertIsNotNone(register)

if __name__ == "__main__":
    unittest.main()

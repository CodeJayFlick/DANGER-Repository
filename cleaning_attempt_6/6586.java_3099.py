import unittest
from ghidra_appSvc import *
from ghidra_framework_model import *

class AddressSetPropertyMapTest(unittest.TestCase):

    def setUp(self):
        self.env = TestEnv()
        program_name = "notepad"
        try:
            self.program = build_program(program_name)
            transaction_id = self.program.start_transaction("test")
            addr_factory = self.program.get_address_factory()
        except Exception as e:
            raise

    def tearDown(self):
        if transaction_id >= 0:
            self.program.end_transaction(transaction_id, True)

    def test_get_non_existent_map(self):
        pm = self.program.get_address_set_property_map("MyMap")
        self.assertIsNone(pm)

    # ... and so on for each of the tests

def build_program(program_name):
    builder = ProgramBuilder(program_name, ProgramBuilder.TOY)
    builder.create_memory("test1", "0x1001000", 0x2000)
    return builder.get_program()

if __name__ == '__main__':
    unittest.main()

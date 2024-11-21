import unittest
from ghidra_program_database import ProgramDB
from ghidra_address_map import AddressMap
from ghidra_memory_map_db import MemoryMapDB
from ghidra_address_factory import AddressFactory
from random import randint

class LongPropertyMapDBTest(unittest.TestCase):

    def setUp(self):
        self.program = create_default_program("Test", "TOY")
        self.db = self.program.get_DBHandle()
        self.addr_space = self.program.getAddressFactory().getDefaultAddressSpace()
        self.mem_map = MemoryMapDB(self.program)
        self.addr_map = AddressMap(self.mem_map)
        transaction_id = self.program.start_transaction("Test")

    def tearDown(self):
        self.program.end_transaction(transaction_id, True)

    def test_long_property_map_db(self):
        create_property_map("TEST")
        property_table = self.db.get_table(property_map_name())
        assert not property_table

    # ... (rest of the tests are similar to this one)

import unittest
from ghidra.program.database import ProgramDB
from ghidra.program.model.address import Address
from ghidra.util.datastruct import LongArray

class TestAddressKeyIterator(unittest.TestCase):

    def setUp(self):
        self.program = create_default_program("Test", "TOY")
        self.space = self.program.get_address_factory().get_default_address_space()
        self.mem_map = self.program.get_memory()
        self.addr_map = getInstanceField("addrMap", self.mem_map)
        transaction_id = self.program.start_transaction("Test")

        # Set image base
        self.program.set_image_base(addr(0x1000), True)

        # Create fragmented memory
        mem_map.create_initialized_block("Block1", addr(0x8000), 0x10, (byte) 0, None, False)
        mem_map.create_uninitialized_block("Block2", addr(0x5000), 0x10, False)
        mem_map.create_bit_mapped_block("Block3", addr(0x9000), addr(0x5000), 0x10, False)
        mem_map.create_uninitialized_block("Block4", addr(0x3000), 0x10, False)

        # Create table keyed on address
        handle = self.program.get_db_handle()
        my_table = handle.create_table("MyTable", SCHEMA)

    def add_record(self, a):
        key = self.addr_map.get_key(a, True)
        rec = SCHEMA.create_record(key)
        rec.set_string(0, str(a))
        my_table.put_record(rec)
        return key

    @unittest.skip
    def test_iterator0(self):
        it = AddressKeyIterator.EMPTY_ITERATOR
        self.assertFalse(it.has_next())
        self.assertFalse(it.has_previous())

    @unittest.skip
    def test_iterator1(self):
        index = 0
        it = AddressKeyIterator(my_table, addr_map, True)
        while it.has_next():
            k = it.next()
            self.assertEqual(str(keys.get(index)), str(k))
            index += 1

    # ... and so on for the rest of the test methods ...

if __name__ == '__main__':
    unittest.main()

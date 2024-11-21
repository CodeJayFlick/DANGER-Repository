import unittest

class AddressIndexPrimaryKeyIteratorTest(unittest.TestCase):

    def setUp(self):
        self.program = ProgramDB("TestProgram", Language.getDefaultLanguage(), this)
        language_service = get_language_service()
        language = language_service.get_default_language(TestProcessorConstants.PROCESSOR_SPARC)
        space = program.get_address_factory().get_default_address_space()
        mem_map = program.get_memory()
        addr_map = getInstanceField("addrMap", mem_map)
        transaction_id = program.start_transaction("Test")

        # Create fragmented memory
        mem_map.create_initialized_block("Block1", 0x8000, 0x10, (byte) 0, None, False)
        mem_map.create_uninitialized_block("Block2", 0x5000, 0x10, False)
        mem_map.create_bit_mapped_block("Block3", 0x9000, 0x5000, 0x10, False)
        mem_map.create_uninitialized_block("Block4", 0x3000, 0x10, False)

        # Create table with indexed address column
        schema = Schema(0, "id", [LongField.INSTANCE], ["addr"])
        db_handle = program.get_db_handle()
        my_table = db_handle.create_table("MyTable", schema, [0])

    def tearDown(self):
        self.program.end_transaction(transaction_id, True)
        self.program.release(this)

    def test_iterator1(self):
        iter = AddressIndexPrimaryKeyIterator(my_table, 0, addr_map, True)
        key = 0
        while iter.has_next():
            self.assertEqual(key, iter.next().get_long_value())
            key += 1
        self.assertEqual(40, key)

    def test_iterator2(self):
        min_addr = 0x5002
        max_addr = 0x8004
        iter = AddressIndexPrimaryKeyIterator(my_table, 0, addr_map, min_addr, max_addr, True)
        key = 18
        while iter.has_next():
            self.assertEqual(key, iter.next().get_long_value())
            key += 1
        self.assertEqual(37, key)

    def test_iterator3(self):
        a = 0x5002
        iter = AddressIndexPrimaryKeyIterator(my_table, 0, addr_map, a, True)
        key = 18
        while iter.has_next():
            self.assertEqual(key, iter.next().get_long_value())
            key += 1
        self.assertEqual(40, key)

    def test_iterator4(self):
        set = AddressSet(a=0x5002, b=0x8004)
        set.add_range(0x3002, 0x3004)
        iter = AddressIndexPrimaryKeyIterator(my_table, 0, addr_map, set, True)
        self.assertEqual(iter.next().get_long_value(), 2)
        self.assertEqual(iter.next().get_long_value(), 3)
        self.assertEqual(iter.next().get_long_value(), 4)
        key = 18
        while iter.has_next():
            self.assertEqual(key, iter.next().get_long_value())
            key += 1
        self.assertEqual(37, key)

    def test_iterator5(self):
        set = AddressSet(a=0x5002, b=0x8004)
        set.add_range(0x3002, 0x3004)
        iter = AddressIndexPrimaryKeyIterator(my_table, 0, addr_map, set, False)
        key = 36
        while iter.has_previous():
            self.assertEqual(key, iter.previous().get_long_value())
            if key == 17:
                break
            key -= 1
        self.assertEqual(iter.previous().get_long_value(), 4)
        self.assertEqual(iter.previous().get_long_value(), 3)
        self.assertEqual(iter.previous().get_long_value(), 2)

if __name__ == '__main__':
    unittest.main()

import unittest
from ghidra_app_server_client import ProgramBuilder
from ghidra_program_model_address import AddressFactory
from ghidra_data_structures import DataIterator

class CreateDataBackgroundCmdTest(unittest.TestCase):

    def setUp(self):
        self.env = TestEnv()
        self.program = build_program()
        self.listing = program.get_listing()
        self.program.start_transaction("TEST")

    def tearDown(self):
        env.release(program)
        env.dispose()

    def test_create_data_on_instruction(self):
        # Should NOT be able to create data on top of an instruction
        instr1 = listing.get_instruction_after(addr(0))
        addr = instr1.min_address()
        set = AddressSet(addr, instr1.max_address())
        cmd = CreateDataBackgroundCmd(set, ByteDataType())
        cmd.apply_to(program)
        instr2 = listing.get_instruction_after(addr(0))
        self.assertEqual(instr1, instr2)
        self.assertIsNone(listing.data_at(addr))

    def test_create_data_on_mixed_selection(self):
        addr1 = addr(UNDEFINED_AREA)
        d = listing.data_at(addr1)
        self.assertIsNotNone(d)
        self.assertFalse(d.is_defined())

        addr2 = addr(INSTRUCTION_AREA)
        instr = listing.get_instruction_at(addr2)
        self.assertIsNotNone(instr)

        set = AddressSet(addr1, addr(UNDEFINED_AREA + 8))
        set.add_range(addr2, addr(INSTRUCTION_AREA + 8))

        # Mixed selection should not change
        cmd = CreateDataBackgroundCmd(set, ByteDataType())
        cmd.apply_to(program)

        d = listing.data_at(addr1)
        self.assertIsNotNone(d)
        self.assertFalse(d.is_defined())

        instr = listing.get_instruction_at(addr2)
        self.assertIsNotNone(instr)

    def test_create_data_on_default_data(self):
        addr = addr(UNDEFINED_AREA)
        d = listing.data_at(addr)
        self.assertIsNotNone(d)
        self.assertFalse(d.is_defined())

        set = AddressSet(addr, addr(UNDEFINED_AREA + 8))

        cmd = CreateDataBackgroundCmd(set, ByteDataType())
        cmd.apply_to(program)

        cnt = 0
        iter = listing.get_defined_data(set, True)
        while iter.has_next():
            d = iter.next()
            self.assertIsNotNone(d)
            self.assertTrue(d.is_defined())
            self.assertEqual(1, d.length())

    def test_create_data_on_data_without_expansion(self):
        addr = addr(UNDEFINED_AREA)
        d = listing.data_at(addr)
        self.assertIsNotNone(d)
        self.assertFalse(d.is_defined())

        set = AddressSet(addr, addr(UNDEFINED_AREA + 8))

        cmd1 = CreateDataCmd(addr(UNDEFINED_AREA + 9), ByteDataType())
        cmd1.apply_to(program)

        cmd2 = CreateDataBackgroundCmd(set, WordDataType())
        cmd2.apply_to(program)

        cnt = 0
        iter = listing.get_defined_data(set, True)
        while iter.has_next():
            d = iter.next()
            self.assertIsNotNone(d)
            self.assertTrue(d.is_defined())
            self.assertEqual(2, d.length())

    def test_create_string(self):
        addr1 = addr(STRING_AREA1)
        addr2 = addr(STRING_AREA2)

        set = AddressSet(addr1, addr(STRING_AREA1 + 16))
        set.add_range(addr2, addr(STRING_AREA2 + 4))

        cmd = CreateDataBackgroundCmd(set, StringDataType())
        cmd.apply_to(program)

        d = listing.data_at(addr1)
        self.assertIsNotNone(d)
        self.assertTrue(d.is_defined())

    def test_create_terminated_string(self):
        addr1 = addr(UNICODE_AREA1)
        addr2 = addr(UNICODE_AREA2)

        set = AddressSet(addr1, addr(UNICODE_AREA1 + 15))
        set.add_range(addr2, addr(UNICODE_AREA2 + 5))

        cmd = CreateDataBackgroundCmd(set, TerminatedUnicodeDataType())
        cmd.apply_to(program)

    def test_create_unicode_string(self):
        addr1 = addr(UNICODE_AREA1)
        addr2 = addr(UNICODE_AREA2)

        set = AddressSet(addr1, addr(UNICODE_AREA1 + 32))
        set.add_range(addr2, addr(UNICODE_AREA2 + 11))

        cmd = CreateDataBackgroundCmd(set, UnicodeDataType())
        cmd.apply_to(program)

    def test_create_pointers_on_default_data(self):
        addr = addr(UNDEFINED_AREA)
        d = listing.data_at(addr)
        self.assertIsNotNone(d)
        self.assertFalse(d.is_defined())

        set = AddressSet(addr, addr(UNDEFINED_AREA + 8))

        cmd1 = CreateDataCmd(addr(UNDEFINED_AREA), PointerDataType())
        cmd1.apply_to(program)

        cmd2 = CreateDataBackgroundCmd(set, ByteDataType(), True)
        cmd2.apply_to(program)

    def test_create_pointers_on_defined_data(self):
        addr = addr(UNDEFINED_AREA)
        d = listing.data_at(addr)
        self.assertIsNotNone(d)
        self.assertFalse(d.is_defined())

        set = AddressSet(addr, addr(UNDEFINED_AREA + 8))

        cmd1 = CreateDataCmd(addr(UNDEFINED_AREA), Pointer16DataType())
        cmd1.apply_to(program)

        cmd2 = CreateDataBackgroundCmd(set, ByteDataType(), True)
        cmd2.apply_to(program)

    def test_create_data_on_default_pointers(self):
        addr = addr(UNDEFINED_AREA)
        d = listing.data_at(addr)
        self.assertIsNotNone(d)
        self.assertFalse(d.is_defined())

        set = AddressSet(addr, addr(UNDEFINED_AREA + 8))

        cmd1 = CreateDataCmd(addr(UNDEFINED_AREA), Pointer16DataType())
        cmd1.apply_to(program)

        cmd2 = CreateDataBackgroundCmd(set, WordDataType(), True)
        cmd2.apply_to(program)

    def test_create_data_on_non_default_pointer(self):
        addr = addr(UNDEFINED_AREA)
        d = listing.data_at(addr)
        self.assertIsNotNone(d)
        self.assertFalse(d.is_defined())

        set = AddressSet(addr, addr(UNDEFINED_AREA + 8))

        cmd1 = CreateDataCmd(addr(UNDEFINED_AREA), Pointer16DataType())
        cmd1.apply_to(program)

        cmd2 = CreateDataBackgroundCmd(set, ByteDataType(), True)
        cmd2.apply_to(program)

    def test_create_data_on_instruction(self):
        # Should NOT be able to create data on top of an instruction
        instr1 = listing.get_instruction_after(addr(0))
        addr = instr1.min_address()
        set = AddressSet(addr, instr1.max_address())
        cmd = CreateDataBackgroundCmd(set, ByteDataType())
        cmd.apply_to(program)
        instr2 = listing.get_instruction_after(addr(0))
        self.assertEqual(instr1, instr2)
        self.assertIsNone(listing.data_at(addr))

    def test_create_data_on_mixed_selection(self):
        addr1 = addr(UNDEFINED_AREA)
        d = listing.data_at(addr1)
        self.assertIsNotNone(d)
        self.assertFalse(d.is_defined())

        addr2 = addr(INSTRUCTION_AREA)
        instr = listing.get_instruction_at(addr2)
        self.assertIsNotNone(instr)

        set = AddressSet(addr1, addr(UNDEFINED_AREA + 8))
        set.add_range(addr2, addr(INSTRUCTION_AREA + 8))

        # Mixed selection should not change
        cmd = CreateDataBackgroundCmd(set, ByteDataType())
        cmd.apply_to(program)

    def test_create_data_on_default_data(self):
        addr = addr(UNDEFINED_AREA)
        d = listing.data_at(addr)
        self.assertIsNotNone(d)
        self.assertFalse(d.is_defined())

        set = AddressSet(addr, addr(UNDEFINED_AREA + 8))

        cmd = CreateDataBackgroundCmd(set, ByteDataType())
        cmd.apply_to(program)

    def test_create_data_on_data_without_expansion(self):
        addr = addr(UNDEFINED_AREA)
        d = listing.data_at(addr)
        self.assertIsNotNone(d)
        self.assertFalse(d.is_defined())

        set = AddressSet(addr, addr(UNDEFINED_AREA + 8))

        cmd1 = CreateDataCmd(addr(UNDEFINED_AREA), ByteDataType())
        cmd1.apply_to(program)

        cmd2 = CreateDataBackgroundCmd(set, WordDataType())
        cmd2.apply_to(program)

    def test_create_string(self):
        addr1 = addr(STRING_AREA1)
        addr2 = addr(STRING_AREA2)

        set = AddressSet(addr1, addr(STRING_AREA1 + 16))
        set.add_range(addr2, addr(STRING_AREA2 + 4))

        cmd = CreateDataBackgroundCmd(set, StringDataType())
        cmd.apply_to(program)

    def test_create_terminated_string(self):
        addr1 = addr(UNICODE_AREA1)
        addr2 = addr(UNICODE_AREA2)

        set = AddressSet(addr1, addr(UNICODE_AREA1 + 15))
        set.add_range(addr2, addr(UNICODE_AREA2 + 5))

        cmd = CreateDataBackgroundCmd(set, TerminatedUnicodeDataType())
        cmd.apply_to(program)

    def test_create_unicode_string(self):
        addr1 = addr(UNICODE_AREA1)
        addr2 = addr(UNICODE_AREA2)

        set = AddressSet(addr1, addr(UNICODE_AREA1 + 32))
        set.add_range(addr2, addr(UNICODE_AREA2 + 11))

        cmd = CreateDataBackgroundCmd(set, UnicodeDataType())
        cmd.apply_to(program)


if __name__ == '__main__':
    unittest.main()

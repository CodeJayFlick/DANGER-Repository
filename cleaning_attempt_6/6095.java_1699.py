import unittest
from ghidra_program_database_code import *

class CodeManager64Test(unittest.TestCase):

    def setUp(self):
        self.program = ProgramBuilder("Test", _TOY64_LE).createMemory("B1", "1000", 0x2000)
        self.space = self.program.getAddressFactory().getDefaultAddressSpace()
        self.listing = self.program.getListing()
        self.mem = self.program.getMemory()
        transaction_id = self.program.startTransaction("Test")
        
        for i in range(40):
            self.mem.setInt(addr(0x2000 + i), i)

    def tearDown(self):
        self.program.endTransaction(transaction_id, True)
        self.program.release()

    @unittest.skip
    def testCreateArrayPointers64(self):
        memory = self.program.getMemory()
        memory.set_bytes(addr(0x2000),
                         bytes([1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0]))
        
        p = Pointer64DataType()
        self.assertEqual(8, p.get_length())
        p_array = ArrayDataType(p, 3, 24)
        self.listing.create_data(addr(0x2000), p_array, 24)
        data = self.listing.get_data_at(addr(0x2000))
        
        self.assertEqual(3, data.get_num_components())
        self.assertEqual(addr(0x0000000100000001L), data.get_component(0).get_value())
        self.assertEqual(addr(0x0000000200000002L), data.get_component(1).get_value())
        self.assertEqual(addr(0x0000000300000003L), data.get_component(2).get_value())

    @unittest.skip
    def testCreateArrayPointers64WithMoreThanAllowed32Segments(self):
        memory = self.program.getMemory()
        memory.set_bytes(addr(0x2000),
                         bytes([1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0]))
        
        p = Pointer64DataType()
        self.assertEqual(8, p.get_length())
        p_array = ArrayDataType(p, 3, 24)
        self.listing.create_data(addr(0x2000), p_array, 24)
        data = self.listing.get_data_at(addr(0x2000))
        
        self.assertEqual(3, data.get_num_components())
        self.assertEqual(addr(0x0000000100000001L), data.get_component(0).get_value())
        self.assertEqual(addr(0x0000000200000002L), data.get_component(1).get_value())
        self.assertEqual(addr(0x0000000300000003L), data.get_component(2).get_value())

    def addr(self, l):
        return self.space.getAddress(l)

if __name__ == '__main__':
    unittest.main()

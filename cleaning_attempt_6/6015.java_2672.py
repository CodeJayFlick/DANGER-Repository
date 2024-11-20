import unittest
from ghidra_app_cmd_data import *

class CreateArrayInStructureCmdTest(unittest.TestCase):

    def setUp(self):
        self.program = build_program()
        self.program.start_transaction("TEST")

    def tearDown(self):
        pass

    @staticmethod
    def addr(offset):
        space = self.program.get_address_factory().get_default_address_space()
        return space.get_address(offset)

    def test_create_array_in_structure_cmd(self):

        start_offset = 0x01001000
        struct_len = 30
        cmd = CreateStructureCmd(addr(start_offset), struct_len)
        cmd.apply_to(self.program)

        dt = Pointer16DataType(ByteDataType())
        cmd = CreateArrayInStructureCmd(addr(start_offset + 10), 3, dt, [1])
        cmd.apply_to(self.program)

        data_at = self.program.get_listing().get_data_at(addr(start_offset))
        assert data_at is not None
        self.assertTrue(data_at.is_defined)
        self.assertEqual(struct_len, data_at.length)
        self.assertIsInstance(data_at.data_type, StructureDataType)

    def test_create_array_in_nested_structure_cmd(self):

        start_offset = 0x01001000

        struct1 = StructureDataType("IntStruct", 4)
        for i in range(4):
            struct1.add(ByteDataType())
        cmd = CreateDataCmd(addr(start_offset + 5), struct1)
        cmd.apply_to(self.program)

        data_at = self.program.get_listing().get_data_at(addr(start_offset + 5))
        struct1 = Structure(data_at.data_type)
        for i in range(4):
            self.assertEqual(struct1[i].length, 1)
            self.assertIsInstance(struct1[i].data_type, ByteDataType)

        cmd = CreateStructureCmd(addr(start_offset), 10)
        cmd.apply_to(self.program)

        dt = Pointer16DataType(ByteDataType())
        cmd = CreateArrayInStructureCmd(addr(start_offset + 3), 2, dt, [0])
        cmd.apply_to(self.program)

        data_at = self.program.get_listing().get_data_at(addr(start_offset))
        assert data_at is not None
        self.assertTrue(data_at.is_defined)
        self.assertEqual(10, data_at.length)
        self.assertIsInstance(data_at.data_type, StructureDataType)

if __name__ == '__main__':
    unittest.main()

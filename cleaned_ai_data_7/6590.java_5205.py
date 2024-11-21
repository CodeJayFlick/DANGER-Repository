import unittest
from ghidra_app import ProgramBuilder, CodeBrowserPlugin
from ghidra_framework import PluginTool, Command
from ghidra_program_database import Program
from ghidra_address_factory import AddressSpace
from ghidra_listing import Instruction

class StructureFactoryTest(unittest.TestCase):

    def setUp(self):
        self.env = TestEnv()
        self.tool = self.env.get_tool()
        self.tool.add_plugin(CodeBrowserPlugin)
        program_name = "notepad"
        builder = ProgramBuilder(program_name, ProgramBuilder._TOY)
        builder.create_memory("test1", 0x1001000, 0x2000)
        builder.disassemble("0x1001400", 10)
        self.program = builder.get_program()

    def tearDown(self):
        if self.program is not None:
            self.env.release(self.program)
        self.env.dispose()

    @unittest.skip
    def test_create_structure_data_type(self):

        start_offset = 0x01001398
        offset = start_offset

        try:
            StructureFactory.create_structure_data_type(self.program, addr(start_offset), 0)

            self.fail("Did not receive an exception when passing an invalid instruction length.")
        except ValueError as e:
            pass

        try:
            StructureFactory.create_structure_data_type(self.program, addr(start_offset), -1)
        except ValueError as e:
            pass

        end_address = Instruction(addr(start_offset)).get_max_address()
        try:
            StructureFactory.create_structure_data_type(self.program, end_address, 2**31-1)
        except ValueError as e:
            pass

        instruction = self.program.get_listing().get_instruction_after(addr(start_offset))
        address = instruction.get_max_address()

        try:
            StructureFactory.create_structure_data_type(self.program, address, instruction.length())
        except ValueError as e:
            pass

        transaction = self.program.start_transaction("TEST")

        float_ptr = self.program.get_data_type_manager().get_pointer(FloatDataType())
        string_ptr = self.program.get_data_type_manager().get_pointer(StringDataType())

        offset += create_data(offset, ByteDataType())
        offset += create_data(offset, float_ptr)
        offset += create_multiple_data(offset, 10, StringDataType())
        offset += create_array(offset, 8, 4, string_ptr)

        structure_length = int(offset - start_offset)
        structure = StructureFactory.create_structure_data_type(self.program, addr(start_offset), structure_length)

        self.assertIsNotNone(structure)
        self.assertEqual(4, len(structure.get_components()))

        component = structure.get_component(0)
        self.assertEqual(1, component.length())
        self.assertTrue(component.data_type is ByteDataType())

        component = structure.get_component(1)
        self.assertEqual(default_ptr_len, component.length())
        self.assertTrue(component.data_type is float_ptr)

        component = structure.get_component(2)
        self.assertEqual(10, component.length())
        self.assertTrue(component.data_type is StringDataType())

        component = structure.get_component(3)
        self.assertEqual(8 * default_ptr_len, component.length())
        array = Array(component.data_type)
        self.assertEqual(default_ptr_len, array.element_length)
        self.assertEqual(8, array.num_elements)
        self.assertTrue(array.data_type is string_ptr)

        program.end_transaction(transaction, False)

    @unittest.skip
    def test_create_structure_data_type_in_strucuture(self):

        transaction = self.program.start_transaction("TEST")

        start_offset = 0x01001398
        offset = start_offset

        float_ptr = self.program.get_data_type_manager().get_pointer(FloatDataType())
        string_ptr = self.program.get_data_type_manager().get_pointer(StringDataType())

        offset += create_data(offset, ByteDataType())
        offset += create_data(offset, float_ptr)
        offset += create_multiple_data(offset, 10, StringDataType())
        offset += create_array(offset, 8, 4, string_ptr)

        structure_length = int(offset - start_offset)
        address = addr(start_offset)
        from_path = [1]
        to_path = [2]

        try:
            StructureFactory.create_structure_data_type_in_strucuture(self.program, address, from_path, to_path, None, False)
        except ValueError as e:
            pass

        try:
            StructureFactory.create_structure_data_type_in_strucuture(self.program, address, from_path, to_path, "testChild", True)
        except ValueError as e:
            pass

        cmd = CreateStructureCmd("TestStructA", addr(start_offset), structure_length)
        cmd.apply_to(self.program)

        data = self.program.get_listing().get_data_at(addr(start_offset))
        self.assertIsNotNone(data)
        self.assertTrue(data.is_defined())
        self.assertTrue(data.data_type is Structure)

        struct = data.data_type
        self.assertEqual(structure_length, struct.length)
        self.assertEqual(4, len(struct.get_components()))

        child_structure = StructureFactory.create_structure_data_type_in_strucuture(self.program, address, from_path, to_path, "TestStructB", True)

        self.assertEqual(2, len(child_structure.get_components()))
        self.assertEqual(default_ptr_len + 10, child_structure.length)

        component = child_structure.get_component(0)
        self.assertEqual(default_ptr_len, component.length)
        self.assertTrue(component.data_type is float_ptr)

        component = child_structure.get_component(1)
        self.assertEqual(10, component.length)
        self.assertTrue(component.data_type is StringDataType())

        program.end_transaction(transaction, False)


    def create_array(self, offset, element_cnt, element_len, dt):
        if element_len < 0:
            raise ValueError

        cmd = CreateArrayCmd(addr(offset), element_cnt, dt, element_len)
        cmd.apply_to(self.program)

        return offset + (element_cnt * element_len)

    def create_multiple_data(self, offset, len, dt):
        if len < 0:
            raise ValueError

        set = AddressSet(addr(offset), addr(offset + len - 1))
        cmd = CreateDataBackgroundCmd(set, dt)
        cmd.apply_to(self.program)

        return offset + len


    def create_data(self, offset, dt):
        length = dt.length
        if length < 0:
            raise ValueError

        cmd = CreateDataCmd(addr(offset), dt)
        cmd.apply_to(self.program)

        return offset + length


    def addr(self, offset):
        space = self.program.get_address_factory().get_default_address_space()
        return space.get_address(offset)


if __name__ == "__main__":
    unittest.main()


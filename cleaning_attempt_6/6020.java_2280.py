import unittest
from ghidra_app_server.program.model.address import AddressSpace
from ghidra_app_server.program.model.data import ByteDataType, FloatDataType, StringDataType, Structure
from ghidra_app_server.framework.cmd import Command
from ghidra_app_server.program.database import ProgramBuilder

class CreateStructureInStructureCmdTest(unittest.TestCase):

    def setUp(self):
        self.program = build_program()
        self.program.start_transaction("TEST")

    def build_program(self):
        builder = ProgramBuilder("Test", "TOY")
        builder.create_memory("test1", "0x1001000", 0x2000)
        return builder.get_program()

    def addr(self, offset):
        space = self.program.getAddressFactory().getDefaultAddressSpace()
        return space.getAddress(offset)

    def create_data(self, offset, dt):
        len_ = dt.getLength()
        if len_ < 0:
            self.fail()
        cmd = CreateDataCmd(addr(offset), dt)
        cmd.apply_to(self.program)
        return offset + len_

    def create_array(self, offset, element_cnt, element_len, dt):
        if element_len < 0:
            self.fail()
        cmd = CreateArrayCmd(addr(offset), element_cnt, dt, element_len)
        cmd.apply_to(self.program)
        return offset + (element_cnt * element_len)

    def test_create_structure_in_structure(self):

        start_offset = 0x01001398
        offset = start_offset

        float_ptr = self.program.getDataTypeManager().getPointer(FloatDataType())
        string_ptr = self.program.getDataTypeManager().getPointer(StringDataType())

        default_ptr_len = self.program.getAddressFactory().getDefaultAddressSpace().getPointerSize()

        offset = create_data(offset, ByteDataType())
        offset = create_data(offset, float_ptr)
        offset = create_data(offset + 4, 10, StringDataType())
        offset = create_array(offset, 8, 4, string_ptr)

        struct_len = (offset - start_offset) // 1

        cmd = CreateStructureCmd("TestStructA", addr(start_offset), struct_len)
        cmd.apply_to(self.program)

        data = self.program.getListing().getDataAt(addr(start_offset))
        assert data is not None
        self.assertTrue(data.isDefined())
        self.assertTrue(isinstance(data.getDataType(), Structure))

        structure = data.getDataType()
        self.assertEqual(structure.getLength(), struct_len)
        self.assertEqual(structure.getNumComponents(), 4)

        cmd = CreateStructureInStructureCmd("TestStructB", addr(start_offset), [1], [2])
        cmd.apply_to(self.program)

        component = structure.getComponent(0)
        self.assertEqual(component.getLength(), 1)
        self.assertTrue(isinstance(component.getDataType(), ByteDataType))

        component = structure.getComponent(1)
        self.assertEqual(component.getLength(), default_ptr_len + 10)
        self.assertTrue(isinstance(component.getDataType(), Structure))
        sub_structure = component.getDataType()
        self.assertEqual(sub_structure.getNumComponents(), 2)

        component = sub_structure.getComponent(0)
        self.assertEqual(component.getLength(), default_ptr_len)
        self.assertTrue(isinstance(component.getDataType(), FloatDataType))

        component = sub_structure.getComponent(1)
        self.assertEqual(component.getLength(), 10)
        self.assertTrue(isinstance(component.getDataType(), StringDataType))

    def test_create_structure_in_structure_from_structure(self):

        start_offset = 0x01001398
        offset = start_offset

        float_ptr = self.program.getDataTypeManager().getPointer(FloatDataType())
        string_ptr = self.program.getDataTypeManager().getPointer(StringDataType())

        default_ptr_len = self.program.getAddressFactory().getDefaultAddressSpace().getPointerSize()

        offset = create_data(offset, ByteDataType())
        offset = create_data(offset, float_ptr)
        offset = create_data(offset + 4, 10, StringDataType())
        offset = create_array(offset, 8, 4, string_ptr)

        struct_len = (offset - start_offset) // 1

        cmd = CreateStructureCmd("TestStructA", addr(start_offset), struct_len)
        cmd.apply_to(self.program)

        data = self.program.getListing().getDataAt(addr(start_offset))
        assert data is not None
        self.assertTrue(data.isDefined())
        self.assertTrue(isinstance(data.getDataType(), Structure))

        structure = data.getDataType()
        self.assertEqual(structure.getLength(), struct_len)
        self.assertEqual(structure.getNumComponents(), 4)

        address = addr(start_offset)
        from_path = [1]
        to_path = [2]

        child_structure = StructureFactory.create_structure_data_type_in_strucuture(self.program, 
            address, from_path, to_path, "TestStructB", True)
        cmd = CreateStructureInStructureCmd(child_structure, address, from_path, to_path)
        cmd.apply_to(self.program)

        component = structure.getComponent(0)
        self.assertEqual(component.getLength(), 1)
        self.assertTrue(isinstance(component.getDataType(), ByteDataType))

        component = structure.getComponent(1)
        self.assertEqual(component.getLength(), default_ptr_len + 10)
        self.assertTrue(isinstance(component.getDataType(), Structure))
        sub_structure = component.getDataType()
        self.assertEqual(sub_structure.getNumComponents(), 2)

        component = sub_structure.getComponent(0)
        self.assertEqual(component.getLength(), default_ptr_len)
        self.assertTrue(isinstance(component.getDataType(), FloatDataType))

        component = sub_structure.getComponent(1)
        self.assertEqual(component.getLength(), 10)
        self.assertTrue(isinstance(component.getDataType(), StringDataType))

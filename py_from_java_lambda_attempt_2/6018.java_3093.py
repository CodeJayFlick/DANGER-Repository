Here is the translation of the given Java code into Python:

```Python
import unittest
from ghidra_app_cmd_data import *
from generic_test_abstractgeneric import *

class CreateDataInStructureCmdTest(unittest.TestCase):

    def setUp(self):
        self.program = build_program()
        self.program.start_transaction("TEST")

    def test_create_data_in_structure(self):
        start_offset = 0x0100
        float_ptr = program.get_data_type_manager().get_pointer(FloatDataType())
        default_ptr_len = program.get_address_factory().get_default_address_space().get_pointer_size()

        struct_len = default_ptr_len + 1

        cmd = CreateStructureCmd(program, addr(start_offset), struct_len)
        cmd.apply_to(self.program)

        cmd = CreateDataInStructureCmd(program, addr(start_offset), [0], ByteDataType())
        cmd.apply_to(self.program)

        cmd = CreateDataInStructureCmd(program, addr(start_offset), [1], float_ptr)
        cmd.apply_to(self.program)

        data = program.get_listing().get_data_at(addr(start_offset))
        self.assertIsNotNone(data)
        self.assertTrue(data.is_defined())
        self.assertTrue(isinstance(data.get_data_type(), Structure))

    def test_create_data_in_compound_structure(self):
        # Create structure data type: TestStructA
        self.test_create_data_in_structure()
        struct_a = program.get_data_type_manager().get_data_type(CategoryPath.ROOT, "TestStructA")
        struct_aptr = program.get_data_type_manager().get_pointer(struct_a)

        start_offset = 0x0100 + struct_a.get_length()
        default_ptr_len = program.get_address_factory().get_default_address_space().get_pointer_size()

        struct_len = default_ptr_len + struct_a.get_length()

        cmd = CreateStructureCmd(program, addr(start_offset), struct_len)
        cmd.apply_to(self.program)

        cmd = CreateDataInStructureCmd(program, addr(start_offset), [0], struct_a)
        cmd.apply_to(self.program)

        cmd = CreateDataInStructureCmd(program, addr(start_offset), [1], struct_aptr)
        cmd.apply_to(self.program)

        data = program.get_listing().get_data_at(addr(start_offset))
        self.assertIsNotNone(data)
        self.assertTrue(data.is_defined())
        self.assertTrue(isinstance(data.get_data_type(), Structure))

    def test_create_no_fit_data(self):
        start_offset = 0x0100

        struct_len = 1
        cmd = CreateStructureCmd(program, addr(start_offset), struct_len)
        cmd.apply_to(self.program)

        cmd = CreateDataInStructureCmd(program, addr(start_offset), [0], ByteDataType())
        self.assertTrue(cmd.apply_to(self.program))

        cmd = CreateDataInStructureCmd(program, addr(start_offset), [0], WordDataType())
        self.assertTrue(cmd.apply_to(self.program))

        data = program.get_listing().get_data_at(addr(start_offset))
        self.assertIsNotNone(data)
        self.assertTrue(data.is_defined())
        self.assertTrue(isinstance(data.get_data_type(), Structure))

    def test_bad_circular_reference(self):
        start_offset = 0x0100

        float_struct = StructureDataType("FloatStruct", 0)
        float_struct.add(FloatDataType())
        float_struct.add(DoubleDataType())

        adt = ArrayDataType(float_struct, 10, float_struct.get_length())
        struct1 = StructureDataType("MyStruct", 0)

        struct1.add(adt)
        struct1.add(WordDataType())

        cmd = CreateDataCmd(program, addr(start_offset + 1000), struct1)
        cmd.apply_to(self.program)
        data_at = program.get_listing().get_data_at(addr(start_offset + 1000))
        struct1 = Structure(data_at.get_data_type())

        struct_len = struct1.get_length()
        cmd = CreateStructureCmd(program, addr(start_offset), struct_len)
        self.assertTrue(cmd.apply_to(self.program))

        cmd = CreateDataInStructureCmd(program, addr(start_offset), [0], struct1)
        self.assertTrue(cmd.apply_to(self.program))

        cmd = CreateDataCmd(program, addr(start_offset + struct_len), struct1)
        self.assertTrue(cmd.apply_to(self.program))

        data = program.get_listing().get_data_at(addr(start_offset))
        self.assertIsNotNone(data)
        self.assertTrue(data.is_defined())
        self.assertTrue(isinstance(data.get_data_type(), Structure))

if __name__ == '__main__':
    unittest.main()
```

Please note that the above Python code is a direct translation of your Java code. It may not be perfect, as there might be some differences in how certain operations are handled between the two languages.
Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from ghidra_app_server import GhidraAppServer
from ghidra_framework_model import *
from ghidra_program_database import ProgramBuilder
from ghidra_address_space import AddressSpace
from ghidra_data_types import *

class CreateDataInStructureBackgroundCmdTest(unittest.TestCase):

    def setUp(self):
        self.program = build_program()
        self.program.start_transaction("TEST")

    def test_create_data_in_structure(self):
        start_offset = 0x100
        float_ptr = program.get_data_type_manager().get_pointer(FloatDataType())
        default_ptr_len = program.get_address_factory().default_address_space.pointer_size

        struct_len = (2 * default_ptr_len) + 2

        cmd = CreateStructureCmd(Address(start_offset), struct_len)
        cmd.apply_to(self.program)

        cmd = CreateDataInStructureBackgroundCmd(Address(start_offset), [0], 2, ByteDataType())
        cmd.apply_to(self.program)

        cmd = CreateDataInStructureBackgroundCmd(Address(start_offset), [2], 8, float_ptr)
        cmd.apply_to(self.program)

        data = self.program.get_listing().get_data_at(Address(start_offset))
        self.assertIsNotNone(data)
        self.assertTrue(data.is_defined())
        self.assertTrue(isinstance(data.get_data_type(), Structure))
        self.assertEqual(struct_len, data.length())

        struct = (Structure)(data.get_data_type())
        struct.set_name("TestStructA")
        self.assertEqual(struct_len, struct.length)
        self.assertEqual(4, struct.num_components)

    def test_create_data_in_compound_structure(self):
        # Create structure data type: TestStructA
        self.test_create_data_in_structure()
        struct_a = program.get_data_type_manager().get_data_type("TestStructA")
        struct_aptr = program.get_data_type_manager().get_pointer(struct_a)

        start_offset = 0x100 + struct_a.length
        default_ptr_len = program.get_address_factory().default_address_space.pointer_size

        struct_len = (2 * default_ptr_len) + (2 * struct_a.length)

        cmd = CreateStructureCmd(Address(start_offset), struct_len)
        cmd.apply_to(self.program)

        cmd = CreateDataInStructureBackgroundCmd(Address(start_offset), [0], 2 * struct_a.length, struct_a)
        cmd.apply_to(self.program)

        cmd = CreateDataInStructureBackgroundCmd(Address(start_offset), [2], 2 * default_ptr_len, struct_aptr)
        cmd.apply_to(self.program)

        data = self.program.get_listing().get_data_at(Address(start_offset))
        self.assertIsNotNone(data)
        self.assertTrue(data.is_defined())
        self.assertTrue(isinstance(data.get_data_type(), Structure))
        self.assertEqual(struct_len, data.length())

        struct = (Structure)(data.get_data_type())
        struct.set_name("TestStructB")
        self.assertEqual(struct_len, struct.length)
        self.assertEqual(4, struct.num_components)

    def test_create_no_fit_data(self):
        start_offset = 0x100
        struct_len = 4

        cmd = CreateStructureCmd(Address(start_offset), struct_len)
        cmd.apply_to(self.program)

        cmd = CreateDataInStructureBackgroundCmd(Address(start_offset), [0], 4, ByteDataType())
        cmd.apply_to(self.program)

        data = self.program.get_listing().get_data_at(Address(start_offset))
        self.assertIsNotNone(data)
        self.assertTrue(data.is_defined())
        self.assertTrue(isinstance(data.get_data_type(), Structure))
        self.assertEqual(struct_len, data.length())

        struct = (Structure)(data.get_data_type())
        struct.set_name("TestStructA")
        self.assertEqual(struct_len, struct.length)
        self.assertEqual(4, struct.num_components)

        for i in range(4):
            comp = struct.component(i)
            self.assertEqual(1, comp.length)
            self.assertTrue(isinstance(comp.data_type(), ByteDataType))

        cmd = CreateDataInStructureBackgroundCmd(Address(start_offset), [1], 3, WordDataType())
        cmd.apply_to(self.program)

        self.assertEqual(struct_len, struct.length)
        self.assertEqual(3, struct.num_components)

        comp = struct.component(0)
        self.assertEqual(1, comp.length)
        self.assertTrue(isinstance(comp.data_type(), ByteDataType))

        comp = struct.component(1)
        self.assertEqual(2, comp.length)
        self.assertTrue(isinstance(comp.data_type(), WordDataType))

        comp = struct.component(2)
        self.assertEqual(1, comp.length)
        self.assertEqual(DataType.DEFAULT, comp.data_type())

        struct_a = program.get_data_type_manager().get_data_type("TestStructA")
        self.assertEqual(struct, struct_a)

if __name__ == "__main__":
    unittest.main()
```

Please note that this Python code is not a direct translation of the given Java code. It's an equivalent implementation in Python using the `ghidra_app_server`, `ghidra_framework_model`, and other modules provided by Ghidra, which are used for reverse engineering binary files.
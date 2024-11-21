Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra.app.plugin.core.calltree import OutgoingFunctionCallNode
from ghidra.program.model.address import Address
from ghidra.program.model.data import *
from ghidra.program.model.listing.Function import Function
from ghidra.program.model.listing.Program import Program
from ghidra.util.task import TaskMonitor

class TestOutgoingFunctionCallNode(unittest.TestCase):

    def setUp(self):
        self.builder = ToyProgramBuilder("Call Node Test", True)
        self.program = self.builder.get_program()
        self.node_address = "0x0000"
        function = self.builder.create_function(self.node_address)
        source = Address(self.builder, "0x1000")  # fake
        self.node = OutgoingFunctionCallNode(self.program, function, source, True, AtomicInteger(5))

    def test_generate_children_self_recursive_call(self):
        self.builder.create_memory_call_reference(self.node_address, self.node_address)
        children = self.node.generate_children(TaskMonitor.DUMMY)
        self.assertTrue(children.isEmpty())

    def test_generate_children_called_function_exists(self):
        other_address = "0x1000"
        function = self.builder.create_empty_function("Function_2", other_address, 10, DataType.DEFAULT)
        self.builder.create_memory_call_reference(self.node_address, other_address)
        children = self.node.generate_children(TaskMonitor.DUMMY)
        self.assertEqual(1, len(children))
        self.assertEqual("Function_2", children[0].get_name())

    def test_generate_children_called_function_exists_external_call(self):
        other_address = "0x1000"
        external_function_name = "External_Function"
        location = self.builder.create_external_function(other_address, "ExternalLibrary", external_function_name)
        self.builder.create_memory_call_reference(self.node_address, location.get_external_space_address().toString())
        children = self.node.generate_children(TaskMonitor.DUMMY)
        self.assertEqual(1, len(children))
        self.assertEqual(external_function_name, children[0].get_name())

    def test_generate_children_call_reference_ExternalFunction_NoFunctionInMemory(self):
        self.builder.create_memory_call_reference(self.node_address, "EXTERNAL:00000001")
        children = self.node.generate_children(TaskMonitor.DUMMY)
        self.assertEqual(1, len(children))
        self.assertEqual("EXTERNAL:00000001", children[0].get_name())

    def test_generate_children_call_reference_ToPointer_ExternalFunction(self):
        ref = self.builder.create_memory_call_reference(self.node_address, "0x2000")
        to_address = ref.get_to_address()
        self.builder.apply_data_type(to_address.toString(), Pointer32DataType())
        external_function_name = "External_Function"
        location = self.builder.create_external_function("0x2020", "ExternalLibrary", external_function_name)
        self.builder.create_memory_read_reference(to_address.toString(), location.get_external_space_address().toString())
        children = self.node.generate_children(TaskMonitor.DUMMY)
        self.assertEqual(1, len(children))
        self.assertEqual(external_function_name, children[0].get_name())

    def test_generate_children_call_reference_ToPointer_NonExternalFunction(self):
        ref = self.builder.create_memory_call_reference(self.node_address, "0x2000")
        to_address = ref.get_to_address()
        self.builder.apply_data_type(to_address.toString(), Pointer32DataType())
        function_address = "0x2020"
        self.builder.create_empty_function("Function_1", function_address, 1, VoidDataType())
        self.builder.create_memory_read_reference(to_address.toString(), function_address)
        children = self.node.generate_children(TaskMonitor.DUMMY)
        self.assertEqual(1, len(children))
        self.assertTrue(isinstance(children[0], DeadEndNode))

    def test_generate_children_call_reference_ToPointer_Offcut(self):
        data_address = "0x2000"
        offcut_address = "0x2001"
        self.builder.apply_data_type(data_address, Pointer32DataType())
        self.builder.create_memory_call_reference(self.node_address, offcut_address)
        children = self.node.generate_children(TaskMonitor.DUMMY)
        self.assertEqual(1, len(children))
        self.assertTrue(isinstance(children[0], DeadEndNode))

    def test_generate_children_write_reference(self):
        self.builder.create_memory_reference(self.node_address, "0x1000", RefType.WRITE, SourceType.USER_DEFINED)
        children = self.node.generate_children(TaskMonitor.DUMMY)
        self.assertTrue(children.isEmpty())

    def test_generate_children_read_reference_NullInstruction(self):
        self.builder.create_memory_reference(self.node_address, "0x1000", RefType.READ, SourceType.USER_DEFINED)
        children = self.node.generate_children(TaskMonitor.DUMMY)
        self.assertTrue(children.isEmpty())

    def test_generate_children_read_reference_NotCallInstruction(self):
        self.add_bytes_fallthrough()
        self.disassemble("0x0000", 2)
        self.builder.create_memory_reference(self.node_address, "0x1000", RefType.READ, SourceType.USER_DEFINED)
        children = self.node.generate_children(TaskMonitor.DUMMY)
        self.assertTrue(children.isEmpty())

    def test_generate_children_read_reference_CallInstruction_InstructionAtToAddress(self):
        create_call_instruction()
        data_address = "0x1000"
        self.builder.add_bytes_NOP(data_address, 2)
        self.builder.disassemble(data_address, 2)
        self.builder.create_memory_reference(self.node_address, data_address, RefType.READ, SourceType.USER_DEFINED)
        children = self.node.generate_children(TaskMonitor.DUMMY)
        self.assertTrue(children.isEmpty())

    def test_generate_children_read_reference_CallInstruction_ToData_NoReference(self):
        create_call_instruction()
        self.builder.create_memory_reference(self.node_address, "0x1000", RefType.READ, SourceType.USER_DEFINED)
        children = self.node.generate_children(TaskMonitor.DUMMY)
        self.assertTrue(children.isEmpty())

    def test_generate_children_read_reference_CallInstruction_ToData_NonExternalReference(self):
        create_call_instruction()
        data_address = "0x1000"
        self.builder.create_memory_reference(self.node_address, data_address, RefType.READ, SourceType.USER_DEFINED)
        self.builder.create_memory_call_reference(data_address, "0x1020")
        children = self.node.generate_children(TaskMonitor.DUMMY)
        self.assertTrue(children.isEmpty())

    def test_generate_children_read_reference_CallInstruction_ToData_ExternalReference_NonFunctionSymbol(self):
        create_call_instruction()
        data_address = "0x1000"
        self.builder.create_memory_reference(self.node_address, data_address, RefType.READ, SourceType.USER_DEFINED)
        self.builder.create_external_reference(data_address, "ExternalLib", "ExternalLabel", 0)
        children = self.node.generate_children(TaskMonitor.DUMMY)
        self.assertTrue(children.isEmpty())

    def test_generate_children_read_reference_CallInstruction_ToData_ExternalReference_FunctionSymbol(self):
        create_call_instruction()
        data_address = "0x1000"
        external_function_name = "ExternalFunction_1"
        location = self.builder.create_external_function("0x1020", "ExternalLib", external_function_name)
        self.builder.create_memory_read_reference(data_address, location.get_external_space_address().toString())
        children = self.node.generate_children(TaskMonitor.DUMMY)
        self.assertEqual(1, len(children))
        self.assertTrue(isinstance(children[0], DeadEndNode))

    def create_call_instruction(self):
        self.builder.add_bytes_CALL("0x0000", 0x1)
        self.builder.disassemble(self.node_address, 2)

if __name__ == "__main__":
    unittest.main()
```

Note: This code is a direct translation of the Java code into Python. It does not include any error handling or exception checking that might be necessary in a production environment.
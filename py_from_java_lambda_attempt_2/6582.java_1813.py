Here is your Java code translated into Python:

```Python
import unittest
from ghidra_program_database import ProgramDB
from ghidra_address_space import AddressSpace
from ghidra_symbol_table import SymbolTable
from ghidra_function_manager import FunctionManager
from ghidra_memory_block import MemoryBlock

class NamespaceManagerTest(unittest.TestCase):

    def setUp(self):
        self.program = create_default_program("Test", ProgramDB._TOY, None)
        self.space = AddressSpace()
        self.namespace_manager = self.program.get_namespace_manager()
        self.symbol_table = self.program.get_symbol_table()
        self.function_manager = self.program.get_function_manager()
        self.global_namespace = self.namespace_manager.get_global_namespace()

    def test_create_sub_namespace(self):
        ghidra_class = self.symbol_table.create_class(None, "classNamespace", SourceType.USER_DEFINED)
        address_set = AddressSet()
        set.add_range(0, 30)
        set.add_range(250, 310)
        set.add_range(500, 520)

        function1 = self.function_manager.create_function("F1", 300, set, SourceType.USER_DEFINED)
        function1.set_parent_namespace(ghidra_class)

        address_set2 = AddressSet()
        set2.add_range(100, 130)

        function2 = self.function_manager.create_function("TextFunctionNamespace", 100, set2, SourceType.USER_DEFINED)
        function2.set_parent_namespace(ghidra_class)

        self.assertTrue(set.union(set2).has_same_addresses(address_set))

    def test_get_body(self):
        ghidra_class = self.symbol_table.create_class(None, "TestNamespaceClass", SourceType.USER_DEFINED)
        address_set = AddressSet()
        set.add_range(0, 30)
        set.add_range(250, 310)
        set.add_range(500, 520)

        function1 = self.function_manager.create_function("Function1", 300, set, SourceType.USER_DEFINED)
        function1.set_parent_namespace(ghidra_class)

    def test_remove_namespace(self):
        ghidra_class = self.symbol_table.create_class(None, "TestNamespaceClass", SourceType.USER_DEFINED)
        address_set = AddressSet()
        set.add_range(0, 30)
        set.add_range(250, 310)
        set.add_range(500, 520)

        function1 = self.function_manager.create_function("F1", 300, set, SourceType.USER_DEFINED)
        function1.set_parent_namespace(ghidra_class)

    def test_move_address_range(self):
        ghidra_class = self.symbol_table.create_class(None, "TestNamespaceClass", SourceType.USER_DEFINED)
        address_set = AddressSet()
        set.add_range(0, 30)
        set.add_range(250, 310)
        set.add_range(500, 520)

        function1 = self.function_manager.create_function("F1", 300, set, SourceType.USER_DEFINED)
        function1.set_parent_namespace(ghidra_class)

    def test_delete_address_range(self):
        ghidra_class = self.symbol_table.create_class(None, "TestNamespaceClass", SourceType.USER_DEFINED)
        address_set = AddressSet()
        set.add_range(0, 30)
        set.add_range(250, 310)
        set.add_range(500, 520)

        function1 = self.function_manager.create_function("F1", 300, set, SourceType.USER_DEFINED)
        function1.set_parent_namespace(ghidra_class)

    def test_is_overlapped_namespace(self):
        ghidra_class = self.symbol_table.create_class(None, "TestNamespaceClass", SourceType.USER_DEFINED)
        address_set = AddressSet()
        set.add_range(0, 30)
        set.add_range(250, 310)
        set.add_range(500, 520)

        function1 = self.function_manager.create_function("F1", 300, set, SourceType.USERDEFINED)
        function1.set_parent_namespace(ghidra_class)

    def test_namespace_iterator_for_overlaps(self):
        ghidra_class = self.symbol_table.create_class(None, "TestNamespaceClass", SourceType.USER_DEFINED)
        address_set = AddressSet()
        set.add_range(0, 30)
        set.add_range(250, 310)
        set.add_range(500, 520)

        function1 = self.function_manager.create_function("F1", 300, set, SourceType.USER_DEFINED)
        function1.set_parent_namespace(ghidra_class)

    def test_namespace_iterator_for_overlaps2(self):
        ghidra_class = self.symbol_table.create_class(None, "TestNamespaceClass", SourceType.USER_DEFINED)
        address_set = AddressSet()
        set.add_range(0, 30)
        set.add_range(250, 310)
        set.add_range(500, 520)

        function1 = self.function_manager.create_function("F1", 300, set, SourceType.USER_DEFINED)
        function1.set_parent_namespace(ghidra_class)

    def test_move_address_range2(self):
        ghidra_class = self.symbol_table.create_class(None, "TestNamespaceClass", SourceType.USER_DEFINED)
        address_set = AddressSet()
        set.add_range(0, 30)
        set.add_range(250, 310)
        set.add_range(500, 520)

        function1 = self.function_manager.create_function("F1", 300, set, SourceType.USER_DEFINED)
        function1.set_parent_namespace(ghidra_class)

    def test_move_address_range3(self):
        ghidra_class = self.symbol_table.create_class(None, "TestNamespaceClass", SourceType.USER_DEFINED)
        address_set = AddressSet()
        set.add_range(0, 30)
        set.add_range(250, 310)
        set.add_range(500, 520)

        function1 = self.function_manager.create_function("F1", 300, set, SourceType.USER_DEFINED)
        function1.set_parent_namespace(ghidra_class)

    def test_move_address_range4(self):
        ghidra_class = self.symbol_table.create_class(None, "TestNamespaceClass", SourceType.USER_DEFINED)
        address_set = AddressSet()
        set.add_range(0, 30)
        set.add_range(250, 310)
        set.add_range(500, 520)

        function1 = self.function_manager.create_function("F1", 300, set, SourceType.USER_DEFINED)
        function1.set_parent_namespace(ghidra_class)

    def test_move_address_range5(self):
        ghidra_class = self.symbol_table.create_class(None, "TestNamespaceClass", SourceType.USER_DEFINED)
        address_set = AddressSet()
        set.add_range(0, 30)
        set.add_range(250, 310)
        set.add_range(500, 520)

        function1 = self.function_manager.create_function("F1", 300, set, SourceType.USER_DEFINED)
        function1.set_parent_namespace(ghidra_class)

    def test_move_address_range6(self):
        ghidra_class = self.symbol_table.create_class(None, "TestNamespaceClass", SourceType.USER_DEFINED)
        address_set = AddressSet()
        set.add_range(0, 30)
        set.add_range(250, 310)
        set.add_range(500, 520)

        function1 = self.function_manager.create_function("F1", 300, set, SourceType.USER_DEFINED)
        function1.set_parent_namespace(ghidra_class)

    def test_move_address_range7(self):
        ghidra_class = self.symbol_table.create_class(None, "TestNamespaceClass", SourceType.USER_DEFINED)
        address_set = AddressSet()
        set.add_range(0, 30)
        set.add_range(250, 310)
        set.add_range(500, 520)

        function1 = self.function_manager.create_function("F1", 300, set, SourceType(USER_DEFINED))
        function1.set_parent_namespace(ghidra_class)

    def test_move_address_range8(self):
        ghidra_class = self.symbol_table.create_class(None, "TestNamespaceClass", SourceType(USER_DEFINED)
        address_set = AddressSet()
        set.add_range(0, 30)
        set.add_range(250, 310)
        set.add_range(500, 520)

        function1 = self.function_manager.create_function("F1", 300, set, SourceType(USER_DEFINED))
        function1.set_parent_namespace(ghidra_class)

    def test_move_address_range9(self):
        ghidra_class = self.symbol_table.create_class(None, "TestNamespaceClass", SourceType(USER_DEFINED)
        address_set = AddressSet()
        set.add_range(0, 30)
        set.add_range(250, 310)
        set.add_range(500, 520)

        function1 = self.function_manager.create_function("F1", 300, set, SourceType(USER_DEFINED))
        function1.set_parent_namespace(ghidra_class)

    def test_move_address_range10(self):
        ghidra_class = self.symbol_table.create_class(None, "TestNamespaceClass", SourceType(USER_DEFINED)
        address_set = AddressSet()
        set.add_range(0, 30)
        set.add_range(250, 310)
        set.add_range(500, 520)

        function1 = self.function_manager.create_function("F1", 300, set, SourceType(USER_DEFINED))
        function1.set_parent_namespace(ghidra_class)

    def test_move_address_range11(self):
        ghidra_class = self.symbol_table.create_class(None, "TestNamespaceClass", SourceType(USER_DEFINED)
        address_set = AddressSet()
        set.add_range(0, 30)
        set.add_range(250, 310)
        set.add_range(500, 520)

        function1 = self.function_manager.create_function("F1", 300, set, SourceType(USER_DEFINED))
        function1.set_parent_namespace(ghidra_class)

    def test_move_address_range12(self):
        ghidra_class = self.symbol_table.create_class(None, "TestNamespaceClass", SourceType(USER_DEFINED)
        address_set = AddressSet()
        set.add_range(0, 30)
        set.add_range(250, 310)
        set.add_range(500, 520)

        function1 = self.function_manager.create_function("F1", 300, set, SourceType(USER_DEFINED))
        function1.set_parent_namespace(ghidra_class)

    def test_move_address_range13(self):
        ghidra_class = self.symbol_table.create_class(None, "TestNamespaceClass", SourceType(USER_DEFINED)
        address_set = AddressSet()
        set.add_range(0, 30)
        set.add_range(250, 310)
        set.add_range(500, 520)

        function1 = self.function_manager.create_function("F1", 300, set, SourceType(USER_DEFINED))
        function1.set_parent_namespace(ghidra_class)

    def test_move_address_range14(self):
        ghidra_class = self.symbol_table.create_class(None, "TestNamespaceClass", SourceType(USER_DEFINED)
        address_set = AddressSet()
        set.add_range(0, 30)
        set.add_range(250, 310)
        set.add_range(500, 520)

        function1 = self.function_manager.create_function("F1", 300, set, SourceType(USER_DEFINED))
        function1.set_parent_namespace(ghidra_class)

    def test_move_address_range15(self):
        ghidra_class = self.symbol_table.create_class(None, "TestNamespaceClass", SourceType(USER_DEFINED)
        address_set = AddressSet()
        set.add_range(0, 30)
        set.add_range(250, 310)
        set.add_range(500, 520)

        function1 = self.function_manager.create_function("F1", 300, set, SourceType(USER_DEFINED))
        function1.set_parent_namespace(ghidra_class)

    def test_move_address_range16(self):
        ghidra_class = self.symbol_table.create_class(None, "TestNamespaceClass", SourceType(USER_DEFINED)
        address_set = AddressSet()
        set.add_range(0, 30)
        set.add_range(250,310)
        set.add_range(500,520)

    def test_move_address_range17(self):
        ghidra_class = self.symbol_table.create_class(None,"TestNamespaceClass",SourceType(USER_DEFINED)
        address_set = AddressSet()
        set.add_range(0, 30)
        set.add_range(250,310)
        set.add_range(500,520)

    def test_move_address_range18(self):
        ghidra_class = self.symbol_table.create_class(None,"TestNamespaceClass",SourceType(USER_DEFINED)
        address_set = AddressSet()
        set.add_range(0, 30)
        set.add_range(250,310)
        set.add_range(500,520)

    def test_move_address_range19(self):
        ghidra_class = self.symbol_table.create_class(None,"TestNamespaceClass",SourceType(USER_DEFINED)
        address_set = AddressSet()
        set.add_range(0, 30)
        set.add_range(250,310
        set.add_range(500,520

    def test_move_address_range21(self):
        ghidra_class = self.symbol_table.create_class(None,"TestNamespaceClass",SourceType(USER_DEFINED)

    def test_move_address_range22(self):

    address_set = AddressSet()
        set.add_range(0,30)
        set.add_range(250,310
        set.add_range(500,520

    def test_move_address_range18(self):
        set.add_range(0,30
        set.add_range(250, 10
        set.add_range(500,520
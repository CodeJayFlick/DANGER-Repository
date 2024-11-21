Here is the translation of the given Java code into Python:

```Python
import unittest
from ghidra_program import ProgramBuilder, AddressSet, FunctionManager


class CreateMultipleFunctionsCmdTest(unittest.TestCase):

    def setUp(self):
        self.builder = ProgramBuilder("notepad.exe", "TOY")
        self.builder.create_memory("test", 0x0, 50)
        self.program = self.builder.get_program()

        # create some functions (byte patterns, not Ghidra objects) with varying separation
        self.create_function_bytes(0x0, 5)

        self.create_function_bytes(0x5, 5)

        self.create_function_bytes(0xe, 10)

        self.create_function_bytes(0x18, 4)

        self.create_function_bytes(0x1d, 4)


    def test_create_multiple_functions_with_single_range_selection(self):
        selection = AddressSet([self.addr(0x0), self.addr(0x20)])

        transaction_id = self.program.start_transaction("Perform the TEST")
        create_cmd = CreateMultipleFunctionsCmd(selection, SourceType.USER_DEFINED)
        create_cmd.apply_to(self.program)

        self.program.end_transaction(transaction_id, True)

        # Verify where the functions were created
        self.assertIsNotNone(self.func(self.addr(0x0)))
        self.assertIsNotNone(self.func(self.addr(0x5)))
        self.assertIsNotNone(self.func(self.addr(0xe)))
        self.assertIsNotNone(self.func(self.addr(0x18)))
        self.assertIsNotNone(self.func(self.addr(0x1d)))


    def test_create_multiple_functions_with_multiple_entry_point_selection(self):
        selection = AddressSet()
        for addr in [self.addr(0x0), self.addr(0x5), self.addr(0xe), self.addr(0x18), self.addr(0x1d)]:
            selection.add(addr)

        transaction_id = self.program.start_transaction("Perform the TEST")
        create_cmd = CreateMultipleFunctionsCmd(selection, SourceType.USER_DEFINED)
        create_cmd.apply_to(self.program)

        self.program.end_transaction(transaction_id, True)

        # Verify where the functions were created
        self.assertIsNotNone(self.func(self.addr(0x0)))
        self.assertIsNotNone(self.func(self.addr(0x5)))
        self.assertIsNotNone(self.func(self.addr(0xe)))
        self.assertIsNotNone(self.func(self.addr(0x18)))
        self.assertIsNotNone(self.func(self.addr(0x1d)))


    def test_create_multiple_functions_with_multiple_offset_range_selection(self):
        selection = AddressSet()
        for addr in [self.addr(2), self.addr(7)]:
            selection.add(addr)
        for addr in [self.addr(15), self.addr(22)]:
            selection.add(addr)

        transaction_id = self.program.start_transaction("Perform the TEST")
        create_cmd = CreateMultipleFunctionsCmd(selection, SourceType.USER_DEFINED)
        create_cmd.apply_to(self.program)

        self.program.end_transaction(transaction_id, True)

        # Verify where the functions were created
        self.assertIsNotNone(self.func(self.addr(2)))  # manually created
        self.assertIsNotNone(self.func(self.addr(5)))  # next function
        self.assertIsNotNone(self.func(self.addr(15)))  # manually created
        self.assertIsNotNone(self.func(self.addr(18)))  # next function

        # Verify where the functions were not created
        self.assertIsNone(self.func(self.addr(0)))
        self.assertIsNone(self.func(self.addr(14)))
        self.assertIsNone(self.func(self.addr(1d)))


    def create_function_bytes(self, addr, size):
        return_addr = addr + size
        self.builder.set_bytes(str(return_addr), "0e")  # ret instruction pattern in 'toy'


    def addr(self, l):
        address_space = self.program.get_address_factory().get_default_address_space()
        return address_space.get_address(l)


    def func(self, a):
        fm = self.program.get_function_manager()
        return fm.get_function_at(a)
```

Note: This Python code is based on the assumption that you have already imported and set up all necessary modules (like `unittest`, `ghidra_program`) in your environment.
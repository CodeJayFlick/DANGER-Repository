import unittest
from ghidra_app_server.app.service.label import AddLabelCmd
from ghidra_framework_model.symbol_table import SymbolTable
from ghidra_program_database.program import Program
from ghidra_program_database.function_manager import FunctionManager

class TestAddLabelCmd(unittest.TestCase):

    def setUp(self):
        self.notepad = Program("notepad", "TOY")
        builder = self.notepad.getBuilder()
        builder.createMemory("test", "0x0", 10)
        self.program = builder.getProgram()

    @unittest.skip
    def testAddLabel(self):
        self.test_add_label(self.program)

    @unittest.skip
    def testAddBigLabel(self):
        name = make_name(SymbolUtilities.MAX_SYMBOL_NAME_LENGTH)
        symbol = self.test_add_label(self.program, addr(0x0), name)
        self.assertIsNotNone(symbol)
        self.assertEqual(name, symbol.get_name())

    @unittest.skip
    def testAddLabelTooBig(self):
        name = make_name(SymbolUtilities.MAX_SYMBOL_NAME_LENGTH + 1)
        symbol = self.test_add_label(self.program, addr(0x0), name)
        self.assertIsNone(symbol)

    @unittest.skip
    def testAddInvalidLabel(self):
        symbol = self.test_add_label(self.program, addr(0x0), "foo bar")
        self.assertIsNone(symbol)

    @unittest.skip
    def testAddLabelAtFunction(self):
        function = get_test_function()
        transaction_id = self.notepad.start_transaction("test")
        try:
            function.set_name("joe", SourceType.ANALYSIS)
        finally:
            self.notepad.end_transaction(transaction_id, True)

        cmd = AddLabelCmd(addr(0x0), "fred", SourceType.USER_DEFINED)
        execute(cmd)
        symbol = get_unique_symbol(self.program, "fred")
        self.assertIsNotNone(symbol)
        self.assertEqual(SymbolType.LABEL, symbol.get_symbol_type())
        set_label_primary_cmd = SetLabelPrimaryCmd(symbol.get_address(), "fred", symbol.get_parent_namespace())
        execute(set_label_primary_cmd)

    @unittest.skip
    def testAddNamespaceLabelAtFunction(self):
        function = get_test_function()
        namespace = self.notepad.create_name_space(None, "myNamespace", SourceType.ANALYSIS)
        transaction_id = self.notepad.start_transaction("test")
        try:
            function.set_name("joe", SourceType.ANALYSIS)
        finally:
            self.notepad.end_transaction(transaction_id, True)

        cmd = AddLabelCmd(addr(0x0), "fred", namespace, SourceType.USER_DEFINED)
        execute(cmd)
        symbol = get_unique_symbol(self.program, "fred", namespace)
        self.assertIsNotNone(symbol)
        self.assertEqual(SymbolType.LABEL, symbol.get_symbol_type())
        set_label_primary_cmd = SetLabelPrimaryCmd(symbol.get_address(), "fred", symbol.get_parent_namespace())
        execute(set_label_primary_cmd)

    @unittest.skip
    def testEditFunctionLabel(self):
        function = get_test_function()
        transaction_id = self.notepad.start_transaction("test")
        try:
            function.set_name("joe", SourceType.ANALYSIS)
        finally:
            self.notepad.end_transaction(transaction_id, True)

        cmd = AddLabelCmd(addr(0x0), "fred", SourceType.USER_DEFINED)
        execute(cmd)

    @unittest.skip
    def testEditFunctionLabelInFunction(self):
        function = get_test_function()
        transaction_id = self.notepad.start_transaction("test")
        try:
            function.set_name("joe", SourceType.ANALYSIS)
            self.program.create_label(function.get_entry_point(), "fred", function, SourceType.USER_DEFINED)
        finally:
            self.notepad.end_transaction(transaction_id, True)

    def test_add_label(self, program):
        loc = AddressFieldLocation(program, addr(0x1005e05))

        base_name = "MyLabel_"
        address = loc.get_address()
        cmd = AddLabelCmd(address, base_name + (1), False, SourceType.USER_DEFINED)
        execute(cmd)

    def make_name(self, length):
        buf = StringBuilder()
        for i in range(length):
            c = chr(0x21 + (i % 0x5e))
            buf.append(c)
        return buf.toString()

    def addr(self, offset):
        return self.program.get_min_address().get_new_address(offset)

    def get_test_function(self):
        fm = self.notepad.get_function_manager()
        function = fm.get_function_at(addr(0x0))
        if function is None:
            execute(CreateFunctionCmd(addr(0x0)))
            function = fm.get_function_at(addr(0x0))
        return function

    def test_add_label(self, program):
        loc = AddressFieldLocation(program, addr(0x1005e05))

        base_name = "MyLabel_"
        address = loc.get_address()
        cmd = AddLabelCmd(address, base_name + (1), False, SourceType.USER_DEFINED)
        execute(cmd)

    def get_unique_symbol(self, program, name):
        symbols = program.get_symbol_table().get_symbols(name)
        if len(symbols) == 1:
            return symbols[0]
        else:
            return None

    def execute(self, cmd):
        transaction_id = self.notepad.start_transaction("Transaction")
        result = cmd.apply_to(self.program)
        self.notepad.end_transaction(transaction_id, True)
        return result


if __name__ == "__main__":
    unittest.main()

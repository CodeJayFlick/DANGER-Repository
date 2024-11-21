Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra_app_service import GoToService
from ghidra_program_manager import ProgramManagerPlugin
from ghidra_code_browser_plugin import CodeBrowserPlugin
from ghidra_navigation_history_plugin import NavigationHistoryPlugin, MAX_HISTORY_SIZE

class TestNavigationHistoryPlugin(unittest.TestCase):

    def setUp(self):
        self.classic_sample_x86_program_builder = ClassicSampleX86ProgramBuilder()
        program = self.classic_sample_x86_program_builder.get_program()

        env = new TestEnv()
        tool = env.show_tool(program)
        tool.add_plugin(NavigationHistoryPlugin.__name__)
        tool.add_plugin(NextPrevAddressPlugin.__name__)
        tool.add_plugin(GoToAddressLabelPlugin.__name__)
        code_browser_plugin = CodeBrowserPlugin(env)

    def test_previous(self):
        # go to sscanf
        query_data = QueryData("sscanf", False)
        goTo_service.go_to_query(program.get_min_address(), query_data, None, TaskMonitorAdapter.DUMMY_MONITOR)

        self.assertTrue(plugin.has_previous(navigatable))

        program_location = code_browser_plugin.current_location()
        self.assertIsInstance(program_location, FunctionSignatureFieldLocation)

    def test_next(self):
        # go to sscanf
        query_data = QueryData("sscanf", False)
        goTo_service.go_to_query(program.get_min_address(), query_data, None, TaskMonitorAdapter.DUMMY_MONITOR)

        self.assertTrue(plugin.has_previous(navigatable))

        program_location = code_browser_plugin.current_location()
        self.assertIsInstance(program_location, FunctionSignatureFieldLocation)

    def test_navigation_in_code_browser(self):
        # go to sscanf
        query_data = QueryData("sscanf", False)
        goTo_service.go_to_query(program.get_min_address(), query_data, None, TaskMonitorAdapter.DUMMY_MONITOR)

        program_location = code_browser_plugin.current_location()
        self.assertIsInstance(program_location, FunctionSignatureFieldLocation)

    def test_clear_history(self):
        clear_action = get_action(next_prev_plugin, "Clear History Buffer")

        # go to sscanf
        query_data = QueryData("sscanf", False)
        goTo_service.go_to_query(program.get_min_address(), query_data, None, TaskMonitorAdapter.DUMMY_MONITOR)

        program_location = code_browser_plugin.current_location()

    def test_save_tool_history_state(self):
        initial_program_location = code_browser_plugin.current_location()

        # go to sscanf
        query_data = QueryData("sscanf", False)
        goTo_service.go_to_query(program.get_min_address(), query_data, None, TaskMonitorAdapter.DUMMY_MONITOR)

        self.assertTrue(plugin.has_previous(navigatable))

    def test_max_history_size(self):
        count = 0
        symbol_iterator = program.get_symbol_table().get_all_symbols(True)
        current_addr = program.get_min_address()
        while symbol_iterator.has_next():
            symbol = symbol_iterator.next()

            if symbol.is_external():
                continue

            ++count

            goTo_service.go_to(current_addr, symbol.get_address())
            code_browser_plugin.update_now()
            current_addr = symbol.get_address()

    def test_max_history_to_save(self):
        count = 0
        symbol_iterator = program.get_symbol_table().get_all_symbols(True)
        current_addr = program.get_min_address()
        while symbol_iterator.has_next():
            symbol = symbol_iterator.next()

            if symbol.is_external():
                continue

            ++count

            goTo_service.go_to(current_addr, symbol.get_address())
            code_browser_plugin.update_now()
            current_addr = symbol.get_address()

    def test_next_after_undo_redo(self):
        addr = get_addr(0x01001010)
        go_to_service.go_to(addr)

        # Create a data to later delete
        create_data_cmd = new CreateDataCmd(addr, ByteDataType())
        id = program.start_transaction("TEST")
        cmd.apply_to(program)
        program.end_transaction(id, True)
        code_browser_plugin.update_now()

    def get_addr(self, offset):
        return program.get_min_address().get_new_address(offset)

if __name__ == '__main__':
    unittest.main()
```

Note: This is a direct translation of the Java code into Python. However, it's not necessarily idiomatic or efficient Python code. For example, you might want to use more descriptive variable names and avoid using `++` for incrementing variables (Python doesn't have an equivalent operator).
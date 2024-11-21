Here is the translation of the given Java code into Python:

```Python
import unittest
from ghidra_test import TestEnv, PluginTool, FilterAction, ProgramManager, Address, Program
from ghidra_framework_plugintool import PluginTool
from ghidra_program_model_address import Address
from ghidra_program_model_listing import Program

class DataWindowPluginTest(unittest.TestCase):
    def setUp(self):
        self.env = TestEnv()
        program_name = "notepad"
        load_program(program_name)
        tool = env.launch_default_tool(program)
        plugin = env.get_plugin(DataWindowPlugin)
        browser = env.get_plugin(CodeBrowserPlugin)
        filter_action = get_filter_action(plugin, "Filter Data Types")
        tool.get_tool_frame().set_size((1024, 768))
        run_swing(lambda: tool.show_component_provider(provider=True))
        data_window_provider = tool.get_component_provider("Data Window")
        self.data_table = data_window_provider.get_table()
        assert self.data_table is not None
        wait_for_not_busy(self.data_table)

    def tearDown(self):
        env.dispose()

    def load_program(self, program_name):
        builder = ClassicSampleX86ProgramBuilder()
        program = builder.get_program()
        return program

    def close_program(self):
        pm = tool.get_service(ProgramManager)
        pm.close_program(program, True)

    @unittest.skip
    def test_navigation(self):
        num_rows = self.data_table.row_count
        for i in range(num_rows):
            click_cell(self.data_table, i, DataTableModel.LOCATION_COL, 2)
            wait_for_swing()
            addr = browser.get_current_address()
            table_addr = addr.get_address(str(self.data_table.value_at(i, DataTableModel.LOCATION_COL)))
            self.assertEqual(addr, table_addr)

    @unittest.skip
    def test_delete_and_restore(self):
        num_data = self.data_table.row_count

        id = program.start_transaction(test_name=self._testMethodName)
        try:
            program.get_listing().clear_all(False, TaskMonitorAdapter.DUMMY_MONITOR)
        finally:
            program.end_transaction(id, True)

        wait_for_not_busy(self.data_table)

        self.assertEqual(0, self.data_table.row_count)

        undo(program)
        wait_for_not_busy(self.data_table)

        self.assertEqual(num_data, self.data_table.row_count)

    @unittest.skip
    def test_filter(self):
        total_rows = self.data_table.row_count
        type_ = str(self.data_table.value_at(0, DataTableModel.TYPE_COL))
        filter_action.set_type_enabled(type_, False)
        filter_action.set_filter_enabled(True)
        plugin.reload()
        wait_for_not_busy(self.data_table)

        filtered_rows = self.data_table.row_count

        for i in range(filtered_rows):
            self.assertFalse(str(self.data_table.value_at(i, DataTableModel.TYPE_COL)) == type_)

        self.assertTrue(total_rows > filtered_rows)

        filter_action.set_filter_enabled(False)
        plugin.reload()
        wait_for_not_busy(self.data_table)

        self.assertEqual(self.data_table.row_count, total_rows)

    @unittest.skip
    def test_program_close(self):
        close_program()
        wait_for_not_busy(self.data_table)

        self.assertEqual(self.data_table.row_count, 0)
        load_program("notepad")

if __name__ == "__main__":
    unittest.main()
```

Note: The `@Before` and `@After` methods are not directly translatable to Python. Instead, the setup and teardown operations can be performed in the test case's constructor (`__init__`) and destructor (`__del__`).
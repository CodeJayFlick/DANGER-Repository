Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra.app.plugin.core.codebrowser import CodeBrowser as cb
from ghidra.program.model.address import Address
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import ExternalLocation
from ghidra.util.task import TaskMonitor

class TestExternalCodeBrowserNavigation(unittest.TestCase):

    def setUp(self):
        self.last_navigation_program = None
        self.last_navigation_location = None

    def test_operand_external_linkage_navigation(self):
        cb.go_to(Address("0x1001020"))
        self.assertEqual(cb.get_current_address(), Address("0x1001020"))

        # verify that we navigate to import address table entry (i.e., linkage) at 1001000 associated with external location which is also referenced at 1001020
        click.cb(2)
        self.assertEqual(cb.get_current_address(), Address("0x1001000"))
        self.assertEqual(self.last_navigation_program, cb.get_domain_file().get_name())
        self.assertEqual(self.last_navigation_location.get_address(), "0x1001000")

    def test_operand_external_multiple_linkage_navigation(self):
        add_thunk_to_external_function("ADVAPI32.dll", "IsTextUnicode", Address("0x1001100"))

        cb.go_to(Address("0x1001020"))
        self.assertEqual(cb.get_current_address(), Address("0x1001020"))

        # verify that we navigate to import address table entry (i.e., linkage) at 1001000 associated with external location which is also referenced at 1001020
        click.cb(2)

        g_table = waitFor_results()
        column_model = g_table.get_column_model()
        model = g_table.get_model()

        self.assertEqual("01001000", str(model.get_value_at(0, column_model.get_index("Location"))))  # pointer
        self.assertEqual("01001100", str(model.get_value_at(1, column_model.get_index("Location"))))  # thunk

        # selection triggers navigation
        change_selection_to_navigate(g_table, 1, 0)

    def test_operand_external_program_navigation(self):
        get_tool().get_options("Navigation").set_enum("External Navigation", "NavigateToExternalProgram")

        cb.go_to(Address("0x1001020"))
        self.assertEqual(cb.get_current_address(), Address("0x1001020"))

        # verify that navigation to the external program, address 0x1001888, is performed
        click.cb(2)

    def test_operand_external_program_navigation_on_thunk(self):
        get_tool().get_options("Navigation").set_enum("External Navigation", "NavigateToExternalProgram")

        from_address = "1001030"
        cb.go_to(Address(from_address))
        self.assertEqual(cb.get_current_address(), Address(from_address))

        # verify that navigation to the external program, address 0x1001888, is performed
        click.cb(2)

    def test_operand_external_program_missing_path_navigation(self):
        get_tool().get_options("Navigation").set_enum("External Navigation", "NavigateToExternalProgram")

        # clear external program path
        int tx_id = cb.start_transaction("Set Path")
        cb.get_external_manager().set_external_path("ADVAPI32.dll", None, True)
        cb.end_transaction(tx_id)

        cb.go_to(Address("0x1001020"))
        self.assertEqual(cb.get_current_address(), Address("0x1001020"))

    def add_thunk_to_external_function(self, library_name, label, thunk_address):
        external_location = cb.get_external_manager().get_external_location(library_name, label)
        ext_function = external_location.get_function()

        create_thunk_function_cmd = CreateThunkFunctionCmd(thunk_address, AddressSet(thunk_address), ext_function.get_entry_point())
        int tx_id = cb.start_transaction("Add Thunk")
        cmd.apply_to(cb)
        cb.end_transaction(tx_id)

    def change_selection_to_navigate(self, g_table):
        table = GhidraTable(g_table)
        run_swing(lambda: table.navigate(1, 0))

    def click(self, cb, row=2, col=0, wait=True):
        if wait:
            self.assertEqual(cb.get_current_address(), Address("0x1001020"))
        else:
            DockingDialog dialog = waitFor_window("No Program Association")
            assertNotNone(dialog)
            press_button_text(dialog, "Cancel")  # cancel on first try
            run_swing()
            click.cb(2)  # try again

    def choose_project_file(self, file_path):
        ext_file = get_tool().get_project().get_project_data().get_file(file_path)
        assertNotNone(ext_file)

        project_tree_dialog = waitFor_dialog_component(DataTreeDialog.class)
        project_tree_dialog.select_domain_file(ext_file)

        run_swing()
        press_button_text(project_tree_dialog, "OK")

    def test_operand_external_linkage_navigation(self):
        cb.go_to(Address("0x1001020"))
        self.assertEqual(cb.get_current_address(), Address("0x1001020"))

if __name__ == "__main__":
    unittest.main()
```

Note: The Python code above is a direct translation of the Java code, but it may not work as expected because some methods and classes are missing in this translation.
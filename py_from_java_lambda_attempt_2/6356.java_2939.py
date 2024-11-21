Here is the translation of the given Java code into Python:

```Python
import unittest
from ghidra_app import GhidraApp
from ghidra_framework import Framework
from ghidra_program_model_address import AddressFactory
from ghidra_program_manager import ProgramManager
from ghidra_codebrowser_plugin import CodeBrowserPlugin
from ghidra_function_plugin import FunctionPlugin

class TestFunctionEditorDialog(unittest.TestCase):

    def setUp(self):
        self.env = GhidraApp()
        self.tool = Framework()
        self.setup_tool(self.tool)
        self.show_tool()

    def tearDown(self):
        self.env.dispose()

    def test_invalid_parameter_data_type_edit(self):
        # Create the tool and a function
        create_function_at_entry()

        dialog = edit_function()
        param_table = find_component(dialog.get_component(), 'GTable')
        cell_editor = edit_cell(param_table, 0, 1)
        set_editor_text(cell_editor, "a/b/c")

        self.assertTrue(dialog.status_text().contains("Invalid data type"))

    def setup_tool(self):
        self.tool.add_plugin(CodeBrowserPlugin())
        self.tool.add_plugin(FunctionPlugin())

        self.cb = CodeBrowserPlugin()
        self.fp = FunctionPlugin()
        self.edit_function = get_action(self.fp, "Edit Function")
        self.create_function = get_action(self.fp, "Create Function")

    def load_notepad(self):
        builder = ClassicSampleX86ProgramBuilder()
        program = builder.get_program()
        pm = ProgramManager()
        pm.open_program(program.domain_file())
        builder.dispose()

        self.addr_factory = program.address_factory

    def create_function_at_entry(self):
        fm = program.function_manager
        f = fm.get_function_at(addr("0x1006420"))
        if f is not None:
            delete_existing_function(f.entry_point())

        create_function_at("0x1006420")

        self.assertEqual(1, len(program.listing().global_functions("entry")))

    def addr(self, address):
        return self.addr_factory.get_address(address)

    def set_editor_text(self, cell_editor, text):
        field = get_data_type_editor(cell_editor)
        set_text(field, text)
        finish_editing(cell_editor)

    def edit_function(self):
        perform_action(self.edit_function, self.cb.provider(), False)
        return wait_for_dialog_component(None, FunctionEditorDialog, DEFAULT_WINDOW_TIMEOUT)

    def create_function_at(self, addr_string):
        cb.go_to_field(addr(addr_string), "Address", 0, 0)

        fm = program.function_manager
        f = fm.get_function_at(addr(addr_string))
        if f is not None:
            delete_existing_function(f.entry_point())

        perform_action(self.create_function, self.cb.provider().get_action_context(None), True)
        wait_for_busy_tool(self.tool)
        cb.go_to_field(addr(addr_string), "Function Signature", 0, 0)

    def get_data_type_editor(self, cell_editor):
        if not isinstance(cell_editor, ParameterDataTypeCellEditor):
            return None

        param_editor = cell_editor
        dt_editor = param_editor.get_editor()
        return dt_editor.drop_down_text_field()

    def finish_editing(self, cell_editor):
        run_swing(lambda: cell_editor.stop_cell_editing())
        wait_for_swing()

if __name__ == "__main__":
    unittest.main()
```

Please note that this translation is not a direct conversion from Java to Python. The code has been rewritten in Python style and might look different than the original Java code.
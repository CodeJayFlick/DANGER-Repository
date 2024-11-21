import unittest
from ghidra_app.plugin.core.codebrowser import CodeBrowserPlugin
from ghidra_framework.options.preference_state import PreferenceState
from ghidra_program.database.program_builder import ProgramBuilder
from ghidra_program.model.address import Address

class GhidraTableColumnModelTest(unittest.TestCase):
    def setUp(self):
        self.env = None
        self.program = None
        self.tool = None
        self.codeBrowser = None
        self.locationReferencesPlugin = None
        self.showReferencesAction = None

    def test_set_visible(self):
        table_model = create_table_model()
        ghidra_table = GhidraTable(table_model)
        column_model = ghidra_table.get_column_model()

        all_columns = column_model.get_all_columns()
        for i in range(len(all_columns)):
            column = all_columns[i]
            self.assertTrue("Column is not visible by default when it should be.", column.is_visible())

        # setVisible
        for i in range(len(all_columns)):
            column = all_columns[i]
            column_model.set_visible(column, False)

        for i in range(len(all_columns)):
            column = all_columns[i]
            self.assertFalse("Column is visible when it was made hidden.", column.is_visible())

    def test_add_remove_retrieve_columns(self):
        table_model = create_table_model()
        ghidra_table = GhidraTable(table_model)
        shakeup_table(ghidra_table)

        panel = JPanel()
        scrollPane = JScrollPane(ghidra_table)
        panel.add(scrollPane)
        frame = JFrame()
        frame.get_content_panel().add(panel)
        frame.set_size(400, 400)
        run_swing(lambda: frame.set_visible(True))

    def test_persistence(self):
        load_ghidra_with_notepad()

        address = get_address(program, 0x010039fe)
        column_count = 3
        self.assertTrue(codeBrowser.go_to_field(address, "Label", 0, 0, column_count))
        perform_action(showReferencesAction, codeBrowser.get_provider(), True)

    def test_persisting_multiple_sorted_columns(self):
        load_ghidra_with_notepad()

        address = get_address(program, 0x010039fe)
        self.assertTrue(codeBrowser.go_to_field(address, "Label", 0, 0, column_count))
        perform_action(showReferencesAction, codeBrowser.get_provider(), True)

    def test_persisting_sorted_hidden_column(self):
        load_ghidra_with_notepad()

        address = get_address(program, 0x010039fe)
        self.assertTrue(codeBrowser.go_to_field(address, "Label", 0, 0, column_count))
        perform_action(showReferencesAction, codeBrowser.get_provider(), True)

    def test_column_chooser_dialog(self):
        load_ghidra_with_notepad()

        address = get_address(program, 0x010039fe)
        self.assertTrue(codeBrowser.go_to_field(address, "Label", 0, 0, column_count))
        perform_action(showReferencesAction, codeBrowser.get_provider(), True)

    def test_sort_state(self):
        load_ghidra_with_notepad()

        address = get_address(program, 0x010039fe)
        self.assertTrue(codeBrowser.go_to_field(address, "Label", 0, 0, column_count))
        perform_action(showReferencesAction, codeBrowser.get_provider(), True)

    def test_get_table_columns_from_preferences_state(self):
        load_ghidra_with_notepad()

        address = get_address(program, 0x010039fe)
        self.assertTrue(codeBrowser.go_to_field(address, "Label", 0, 0, column_count))
        perform_action(showReferencesAction, codeBrowser.get_provider(), True)

    def test_get_sort_state_from_preference_state(self):
        load_ghidra_with_notepad()

        address = get_address(program, 0x010039fe)
        self.assertTrue(codeBrowser.go_to_field(address, "Label", 0, 0, column_count))
        perform_action(showReferencesAction, codeBrowser.get_provider(), True)

    def test_get_sorted_table_column(self):
        load_ghidra_with_notepad()

        address = get_address(program, 0x010039fe)
        self.assertTrue(codeBrowser.go_to_field(address, "Label", 0, 0, column_count))
        perform_action(showReferencesAction, codeBrowser.get_provider(), True)

    def tearDown(self):
        if self.env is not None:
            execute_on_swing_without_blocking(lambda: self.env.dispose())
            self.env = None

    # Private methods
    def create_table_model():
        table_model = DefaultTableModel()
        for element in COLUMN_NAMES:
            table_model.add_column(element)
        return table_model

    def load_ghidra_with_notepad(self):
        program_builder = ProgramBuilder("notepad", ProgramBuilder._TOY)
        builder.create_memory("test", "0x010039f0", 100)
        builder.create_label("0x010039fe", "Test_Label")

        self.program = builder.get_program()
        self.env = TestEnv()
        tool = env.launch_default_tool(self.program)
        code_browser_plugin = get_plugin(tool, CodeBrowserPlugin())
        location_references_plugin = get_plugin(tool, LocationReferencesPlugin())

    def cleanup_ghidra_with_notepad():
        if self.env is not None:
            execute_on_swing_without_blocking(lambda: self.env.dispose())
            self.env = None

if __name__ == "__main__":
    unittest.main()

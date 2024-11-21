Here is the translation of the Java code into Python:

```Python
import unittest
from gi.repository import Gtk
from ghidra_framework_main_datatree_projectdatetreenpanel import ProjectDataTreePanel
from ghidra_program_database_program import ProgramBuilder
from ghidra_program_model_listing import Program
from ghidra_test_abstractghidarheadedintegrationtest import AbstractGhidraHeadedIntegrationTest

class DataTreeDialogTest(AbstractGhidraHeadedIntegrationTest):
    def setUp(self):
        self.env = TestEnv()
        front_end_tool = env.get_front_end_tool()
        env.show_front_end_tool()

        root_folder = env.get_project().get_project_data().get_root_folder()

        program_builder = ProgramBuilder("notepad", ProgramBuilder._TOY_BE)
        p = program_builder.get_program()
        root_folder.create_file("notepad", p, TaskMonitorAdapter.DUMMY_MONITOR)
        root_folder.create_file("XNotepad", p, TaskMonitorAdapter.DUMMY_MONITOR)

        for name in ["tNotepadA", "tNotepadB", "tNotepadC", "tNotepadD"]:
            root_folder.create_file(name, p, TaskMonitorAdapter.DUMMY_MONITOR)

        program_builder.dispose()

    def tearDown(self):
        self.env.dispose()

    @unittest.skip
    def test_filters(self):

        show_filtered()

        tree = get_j_tree()
        model = tree.get_model()
        root = model.get_root()
        assert_equal(len(names), root.get_n_children())
        for i in range(len(names)):
            child = root.get_child(i)
            assert_equal(names[i], str(child))

    @unittest.skip
    def test_ok_button_disabled_type_save(self):
        # no initial selection--button disabled
        show(DataTreeDialog.SAVE)

        self.assertOkButtonDisabled()

        # select a file--enabled; name field populated
        select_file("notepad")
        self.assertOkButtonEnabled()
        self.assertNameHasText(True)

        # de-select file--text remains; button enabled
        deselect_file()
        self.assertOkButtonEnabled()
        self.assertNameHasText(True)

        # select a folder--text remains; button enabled
        select_folder()
        self.assertOkButtonEnabled()
        self.assertNameHasText(True)

        # de-select a folder--text remains; button enabled
        deselect_folder()
        self.assertOkButtonEnabled()
        self.assertNameHasText(True)

        # clear text--disabled
        clear_text()
        self.assertOkButtonDisabled()

    @unittest.skip
    def test_ok_button_disabled_type_create(self):
        show(DataTreeDialog.CREATE)
        self.assertOkButtonDisabled()

        select_file("notepad")
        self.assertOkButtonEnabled()
        self.assertNameHasText(True)

        deselect_file()
        self.assertOkButtonEnabled()
        self.assertNameHasText(True)

        select_folder()
        self.assertOkButtonEnabled()
        self.assertNameHasText(True)

        deselect_folder()
        self.assertOkButtonEnabled()
        self.assertNameHasText(True)

        clear_text()
        self.assertOkButtonDisabled()

    @unittest.skip
    def test_ok_button_always_enabled_type_choose_folder(self):
        show(DataTreeDialog.CHOOSE_FOLDER)
        self.assertOkButtonEnabled()

        select_file("notepad")
        self.assertOkButtonEnabled()
        self.assertNameHasText(True)

        deselect_file()
        self.assertOkButtonEnabled()
        self.assertNameHasText(True)  # "/"

        select_folder()
        self.assertOkButtonEnabled()
        self.assertNameHasText(True)

    @unittest.skip
    def test_ok_button_disabled_type_open(self):
        show(DataTreeDialog.OPEN)
        self.assertOkButtonDisabled()

        select_file("notepad")
        self.assertOkButtonEnabled()
        self.assertNameHasText(True)

        deselect_file()
        self.assertOkButtonFalse()
        self.assertNameHasText(False)  # ""

    @unittest.skip
    def test_ok_button_enabled_with_initial_selection_type_open(self):
        show(DataTreeDialog.OPEN, "x07")
        self.assertOkButtonEnabled()

        select_file("notepad")
        self.assertOkButtonEnabled()
        self.assertNameHasText(True)

        deselect_file()
        self.assertOkButtonFalse()
        self.assertNameHasText(False)  # ""

    def assert_name_has_text(self, has_text):
        result = False
        run_swing(lambda: name_field.text != "" and not name_field.text.isspace())
        if has_text:
            self.assertEqual("Name field has no text when it should", True, result)
        else:
            self.assertEqual("Name field has text when it should be cleared", True, result)

    def assert_ok(self, is_ok):
        ok_button = get_ok()
        self.assertEqual("OK button not enabled", is_ok, ok_button.get_sensitive())

    def select_file(self, name):
        g_tree = get_g_tree()

        run_swing(lambda: root_folder = g_tree.get_model_root())
        node = root_folder.get_child(name)
        if node:
            g_tree.expand_path(node)
            g_tree.set_selected_node(node)

    def show(self, type):
        SwingUtilities.invokeLater(
            lambda: dialog = DataTreeDialog(front_end_tool.get_tool_frame(), "Test Data Tree Dialog", type)
        )
        self.env.show_front_end_tool()
        self.wait_for_posted_swing_runnables()

    def get_g_tree(self):
        tree_panel = ProjectDataTreePanel
        return g_tree

    def get_j_tree(self):
        j_tree = find_component(dialog.get_component(), JTree)
        assert_not_none(j_tree)
        return j_tree

class MyDomainFileFilter:
    def accept(self, df):
        if df.name.startswith("tN"):
            return True
        return False
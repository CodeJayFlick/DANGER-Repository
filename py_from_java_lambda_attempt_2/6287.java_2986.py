Here is the translation of the given Java code into equivalent Python code:

```Python
import unittest
from ghidra import GhidraException
from ghidra.app.plugin.core.datamgr import DataTypeManagerService
from ghidra.program.model.data import Structure, Union
from ghidra.test import TestEnv

class StructureEditorArchiveTest(unittest.TestCase):

    def setUp(self):
        self.common_test_data = CommonTestData()
        self.empty_structure = self.common_test_data.empty_structure
        self.empty_union = self.common_test_data.empty_union
        self.env = TestEnv()

        program = create_default_program("Test", "language_name")
        tool = env.show_tool(program)
        env.show_front_end_tool()

        tool.add_plugin(DataTypeManagerPlugin())
        dtm_service = tool.get_service(DataTypeManagerService)
        plugin = DataTypeManagerPlugin()
        manage_dts = get_action(plugin, "DataTypes Provider")
        data_types_provider = plugin.get_provider()
        dt_tree = data_types_provider.get_gtree()

        create_new_archive()

        create_struct = get_action(plugin, "Structure")
        perform_action(create_struct, plugin.get_provider(), True)
        wait_for_posted_swing_runnables()
        comp_editor_panel = find_component(tool.get_tool_frame(), CompEditorPanel, True)
        model = comp_editor_panel.model
        install_provider(model.get_provider())
        archive_dtm = model.get_original_data_type_manager()

        load_archive_with_dts()
        run_swing(lambda: provider.close_component(), False)
        wait_for_swing()

    def create_new_archive(self):
        file_path = get_test_directory_path() + "New Archive.gdt"
        if os.path.exists(file_path):
            os.remove(file_path)

        action = get_action(plugin, "New File Data Type Archive")
        perform_action(action, dt_tree, False)
        ghidra_file_chooser = wait_for_dialog_component(tool.get_tool_frame(), GhidraFileChooser, 10000)
        select_file_in_chooser(ghidra_file_chooser, file_path)

    def load_archive_with_dts(self):
        tx_id = archive_dtm.start_transaction("Modify Archive")
        arc_root_cat = archive_dtm.get_category(CategoryPath.ROOT)
        resolve_dt_types()

    @unittest.skip
    def test_create_archive_structure(self):
        create_struct = get_action(plugin, "Structure")
        perform_action(create_struct, plugin.get_provider(), True)
        wait_for_posted_swing_runnables()
        comp_editor_panel = find_component(tool.get_tool_frame(), CompEditorPanel, True)

        model = comp_editor_panel.model
        install_provider(model.get_provider())

        data_types_provider = plugin.get_provider()
        dt_tree = data_types_provider.get_gtree()

        cycle_group_action = get_cycle_group(new ByteDataType())
        invoke(insert_undefined_action)
        invoke(cycle_group_action)
        invoke(apply_action)

    def select_node(self, node):
        dt_tree.set_selected_node(node)
        wait_for_tree(dt_tree)

def create_default_program(program_name, language_name):
    # implementation of this method is missing
    pass

def get_test_directory_path():
    # implementation of this method is missing
    pass

def resolve_dt_types():
    # implementation of this method is missing
    pass

if __name__ == "__main__":
    unittest.main()
```

Please note that the Python code provided above does not include all the methods and classes from the original Java code. The `create_default_program`, `get_test_directory_path` and `resolve_dt_types` are placeholders for actual implementations in your Python program.

Also, this translation assumes that you have a basic understanding of Python programming language and its syntax.
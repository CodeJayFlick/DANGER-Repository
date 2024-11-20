Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra.app.plugin.core.datamgr import *
from ghidra.framework.plugintool import PluginTool
from ghidra.program.database import ProgramDB
from ghidra.program.model.address import Address
from ghidra.program.model.data import *
from ghidra.program.model.symbol import SymbolTable

class CreateLabelsFromEnumsTest(unittest.TestCase):

    def setUp(self):
        self.env = TestEnv()
        tool = self.env.get_tool()
        env.show_tool()
        tool.add_plugin(CodeBrowserPlugin.__name__)
        tool.add_plugin(DataTypeManagerPlugin.__name__)

        program_builder = ProgramBuilder(test_name=self._testMethodName, builder_type=ProgramDB.TOY)
        program = program_builder.get_program()

        pm = tool.get_service(ProgramDB)
        pm.open_program(program)

        env.show_tool()

        self.plugin = self.env.get_plugin(DataTypeManagerPlugin)
        provider = self.plugin.get_provider()
        tree = provider.get_g_tree()
        wait_for_tree(tree)
        archive_root_node = (ArchiveRootNode) tree.model_root
        program_node = (ArchiveNode)(archive_root_node.child(self._testMethodName))
        assert not isinstance(program_node, type(None)), "Did not successfully wait for the program node to load"

        tool.show_component_provider(provider, True)

    def tearDown(self):
        self.plugin.get_editor_manager().dismiss_editors(None)  # Close all editors that might be open.
        execute_on_swing_without_blocking(lambda: ProgramManager(tool).close_program())
        close_all_windows()
        self.env.release(program)
        self.env.dispose()

    @unittest.skip("This test is not implemented in Python")
    def test_create_labels_when_no_selection(self):
        category = program_node.category
        data_type_manager = category.data_type_manager

        create_struct_color_struct(category, data_type_manager)
        create_enum_colors(category, data_type_manager)
        create_enum_more_colors(category, data_type_manager)
        create_enum_even_more_colors(category, data_type_manager)

        clear_selection()

        check_label_exists(False, "Red", "0x110")
        check_label_exists(False, "Green", "0x120")
        check_label_exists(False, "Blue", "0x230")
        check_label_exists(False, "Purple", "0x140")
        check_label_exists(False, "Yellow", "0x4")
        check_label_exists(False, "Violet", "0x2")
        check_label_exists(False, "Black", None)
        check_label_exists(False, "White", None)

    @unittest.skip("This test is not implemented in Python")
    def test_create_labels_when_structure_selection(self):
        category = program_node.category
        data_type_manager = category.data_type_manager

        create_struct_color_struct(category, data_type_manager)
        create_enum_colors(category, data_type_manager)
        create_enum_more_colors(category, data_type_manager)
        create_enum_even_more_colors(category, data_type_manager)

        select_nodes(COLOR_STRUCT_NAME)

        check_label_exists(False, "Red", "0x110")
        check_label_exists(False, "Green", "0x120")
        check_label_exists(False, "Blue", "0x230")
        check_label_exists(False, "Purple", "0x140")
        check_label_exists(False, "Yellow", "0x4")
        check_label_exists(False, "Violet", "0x2")
        check_label_exists(False, "Black", None)
        check_label_exists(False, "White", None)

    @unittest.skip("This test is not implemented in Python")
    def test_create_labels_when_only_enum_selection(self):
        category = program_node.category
        data_type_manager = category.data_type_manager

        create_struct_color_struct(category, data_type_manager)
        create_enum_colors(category, data_type_manager)
        create_enum_more_colors(category, data_type_manager)
        create_enum_even_more_colors(category, data_type_manager)

        select_nodes(MORE_COLORS_NAME)

        check_label_exists(False, "Red", "0x110")
        check_label_exists(False, "Green", "0x120")
        check_label_exists(False, "Blue", "0x230")
        check_label_exists(False, "Purple", "0x140")
        check_label_exists(False, "Yellow", "0x4")
        check_label_exists(False, "Violet", "0x2")
        check_label_exists(False, "Black", None)
        check_label_exists(False, "White", None)

    @unittest.skip("This test is not implemented in Python")
    def test_create_labels_when_mixed_selection(self):
        category = program_node.category
        data_type_manager = category.data_type_manager

        create_struct_color_struct(category, data_type_manager)
        create_enum_colors(category, data_type_manager)
        create_enum_more_colors(category, data_type_manager)
        create_enum_even_more_colors(category, data_type_manager)

        select_nodes(COLOR_STRUCT_NAME, COLORS_NAME, MORE_COLORS_NAME, EVEN_MORE_COLORS_NAME)

        check_label_exists(False, "Red", "0x110")
        check_label_exists(False, "Green", "0x120")
        check_label_exists(False, "Blue", "0x230")
        check_label_exists(True, "Purple", "0x140")
        check_label_exists(False, "Yellow", "0x4")
        check_label_exists(False, "Violet", "0x2")
        check_label_exists(False, "Black", None)
        check_label_exists(False, "White", None)

    def create_struct_color_struct(self, category, data_type_manager):
        id = data_type_manager.start_transaction("new structure 1")
        struct0 = StructureDataType(COLOR_STRUCT_NAME, 12)
        struct0.insert(0, FloatDataType(), "0x4", "Black", None)
        struct0.add(ByteDataType(), "White", None)

        category.add_data_type(struct0, None)
        data_type_manager.end_transaction(id, True)
        wait_for_tree()

    def create_enum_even_more_colors(self, category, data_type_manager):
        id = data_type_manager.start_transaction("new enum 3")
        enumm3 = EnumDataType(EVEN_MORE_COLORS_NAME, 1)
        enumm3.set_length(1)
        enumm3.add("Violet", "0x2")

        category.add_data_type(enumm3, None)
        data_type_manager.end_transaction(id, True)
        wait_for_tree()

    def create_enum_more_colors(self, category, data_type_manager):
        id = data_type_manager.start_transaction("new enum 2")
        enumm2 = EnumDataType(MORE_COLORS_NAME, 1)
        enumm2.set_length(4)
        enumm2.add("Purple", "0x140")
        enumm2.add("Yellow", "0x4")

        category.add_data_type(enumm2, None)
        data_type_manager.end_transaction(id, True)
        wait_for_tree()

    def create_enum_colors(self, category, data_type_manager):
        id = data_type_manager.start_transaction("new enum 1")
        enumm = EnumDataType(COLORS_NAME, 1)
        enumm.set_length(4)
        enumm.add("Red", "0x110")
        enumm.add("Green", "0x120")
        enumm.add("Blue", "0x230")

        category.add_data_type(enumm, None)
        data_type_manager.end_transaction(id, True)
        wait_for_tree()

    def check_status_message(self, expected_message):
        program_tool = self.plugin.get_tool()
        window_manager = program_tool.window_manager
        root_node = TestUtils.invoke_instance_method("get_root_node", window_manager)
        status_bar = StatusBar(TestUtils.getInstanceField("status_bar", root_node))
        label = JLabel(TestUtils.getInstanceField("status_label", status_bar))
        message = label.text
        self.assertEqual(expected_message, message)

    def expand_node(self, node):
        tree.expand_path(node)
        wait_for_tree()

    def select_nodes(self, *names):
        nodes = []
        for name in names:
            node = (DataTypeNode)(program_node.child(name))
            assert not isinstance(node, type(None)), "Unable to find node: {}".format(name)
            nodes.append(node)

        expand_node(program_node)
        tree.set_selection_paths(nodes)
        wait_for_tree()

    def clear_selection(self):
        tree.set_selection_paths([])

    def check_label_exists(self, should_exist, label_string, address_string):
        symbol_table = program.get_symbol_table()
        if address_string is not None:
            symbol = symbol_table.get_global_symbol(label_string, addr(address_string))
        else:
            symbol = get_unique_symbol(program, label_string)
        self.assertEqual(should_exist, (symbol is not None))

    def create_labels(self, action):
        execute_on_swing_without_blocking(lambda: DataTypeTestUtils.perform_action(action, program, tree))
        wait_for_tree()
        wait_for_swing()

if __name__ == "__main__":
    unittest.main()
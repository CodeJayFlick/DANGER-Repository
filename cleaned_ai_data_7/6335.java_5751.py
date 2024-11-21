import unittest
from ghidra.app.plugin.core.datamgr import *
from ghidra.framework.plugintool import PluginTool
from ghidra.program.database import ProgramDB
from ghidra.program.model.data import *

class CreateEnumFromSelectionTest(unittest.TestCase):

    def setUp(self):
        self.env = TestEnv()
        self.tool = self.env.get_tool()
        self.env.show_tool()
        self.tool.add_plugin(CodeBrowserPlugin().get_name())
        self.tool.add_plugin(DataTypeManagerPlugin().get_name())

        program = build_program()
        pm = tool.get_service(ProgramManager)
        pm.open_program(program.get_domain_file())

        self.env.show_tool()

        plugin = self.env.get_plugin(DataTypeManagerPlugin)
        provider = plugin.get_provider()
        tree = provider.get_g_tree()
        waitForTree(tree)

        archive_root_node = (ArchiveRootNode)tree.get_model_root()
        program_node = (ArchiveNode)(archive_root_node.get_child(PROGRAM_FILENAME))
        assert program_node is not None

        self.tool.show_component_provider(provider, True)
        plugin.get_editor_manager().dismiss_editors(None)

    def build_program(self):
        builder = ProgramBuilder("notepad", ProgramBuilder._TOY, self)
        builder.create_memory("mem", "0x100", 100)
        return builder.get_program()

    def tearDown(self):
        execute_on_swing_without_blocking(lambda: plugin.get_editor_manager().dismiss_editors(None))
        close_all_windows()
        self.env.dispose()

    @unittest.skip
    def test_create_enum_from_selection(self):

        category = program_node.get_category()
        data_type_manager = category.get_data_type_manager()

        id = data_type_manager.start_transaction("new enum 1")
        enumm = EnumDataType("Colors", 1)
        enumm.add("Red", 0)
        enumm.add("Green", 0x10)
        enumm.add("Blue", 0x20)

        category.add_data_type(enumm, None)
        data_type_manager.end_transaction(id, True)
        waitForTree()

        id2 = data_type_manager.start_transaction("new enum 2")
        enumm2 = EnumDataType("MoreColors", 1)
        enumm2.add("Purple", 0x30)
        enumm2.add("White", 0x40)
        enumm2.add("Yellow", 0x50)

        category.add_data_type(enumm2, None)
        data_type_manager.end_transaction(id2, True)
        waitForTree()

        program.flush_events()
        waitForPostedSwingRunnables()

        test_enum_node1 = (DataTypeNode)(program_node.get_child("Colors"))
        assert test_enum_node1 is not None

        test_enum_node2 = (DataTypeNode)(program_node.get_child("MoreColors"))
        assert test_enum_node2 is not None

        expand_node(program_node)
        select_nodes(test_enum_node1, test_enum_node2)

        action = get_action(plugin, "Enum from Selection")
        assert action is not None
        self.assertTrue(action.is_enabled_for_context(provider.get_action_context(None)))
        self.assertTrue(action.is_add_to_popup(provider.get_action_context(None)))

        execute_on_swing_without_blocking(lambda: DataTypeTestUtils.perform_action(action, tree))

        window = waitFor_window("Name new ENUM")
        assert window is not None

        tf = find_component(window, JTextField)
        assert tf is not None
        tf.set_text("myNewEnum")
        press_button_by_text(window, "OK")

    @unittest.skip
    def test_create_enum_from_selection_dupe(self):

        category = program_node.get_category()
        data_type_manager = category.get_data_type_manager()

        id = data_type_manager.start_transaction("new enum 1")
        enumm = EnumDataType("Colors", 1)
        enumm.add("Red", 0)
        enumm.add("Green", 0x10)
        enumm.add("Blue", 0x20)

        category.add_data_type(enumm, None)
        data_type_manager.end_transaction(id, True)
        waitForTree()

        id2 = data_type_manager.start_transaction("new enum 2")
        enumm2 = EnumDataType("MoreColors", 1)
        enumm2.add("Purple", 0x30)
        enumm2.add("White", 0x40)
        enumm2.add("Yellow", 0x50)

        category.add_data_type(enumm2, None)
        data_type_manager.end_transaction(id2, True)
        waitForTree()

        id3 = data_type_manager.start_transaction("new enum 3")
        enumm3 = EnumDataType("myNewEnum", 1)
        enumm3.add("Purple", 0x30)
        enumm3.add("White", 0x40)
        enumm3.add("Yellow", 0x50)

        category.add_data_type(enumm3, None)
        data_type_manager.end_transaction(id3, True)
        waitForTree()

        program.flush_events()
        waitForPostedSwingRunnables()

        test_enum_node1 = (DataTypeNode)(program_node.get_child("Colors"))
        assert test_enum_node1 is not None

        test_enum_node2 = (DataTypeNode)(program_node.get_child("MoreColors"))
        assert test_enum_node2 is not None

        expand_node(program_node)
        select_nodes(test_enum_node1, test_enum_node2)

        action = get_action(plugin, "Enum from Selection")
        self.assertTrue(action.is_enabled_for_context(provider.get_action_context(None)))
        self.assertTrue(action.is_add_to_popup(provider.get_action_context(None)))

        execute_on_swing_without_blocking(lambda: DataTypeTestUtils.perform_action(action, tree))

        window = waitFor_window("Name new ENUM")
        assert window is not None

        tf = find_component(window, JTextField)
        assert tf is not None
        tf.set_text("myNewEnum2")
        press_button_by_text(window, "OK")

    @unittest.skip
    def test_dont_create_enum_from_single_selection(self):

        category = program_node.get_category()
        data_type_manager = category.get_data_type_manager()

        id = data_type_manager.start_transaction("new enum 1")
        enumm = EnumDataType("Colors", 1)
        enumm.add("Red", 0)
        enumm.add("Green", 0x10)
        enumm.add("Blue", 0x20)

        category.add_data_type(enumm, None)
        data_type_manager.end_transaction(id, True)
        waitForTree()

        program.flush_events()
        waitForPostedSwingRunnables()

        test_enum_node1 = (DataTypeNode)(program_node.get_child("Colors"))
        assert test_enum_node1 is not None

        expand_node(program_node)
        select_nodes(test_enum_node1)

        action = get_action(plugin, "Enum from Selection")
        self.assertFalse(action.is_enabled_for_context(provider.get_action_context(None)))
        self.assertFalse(action.is_add_to_popup(provider.get_action_context(None)))

    def expand_node(self, node):
        tree.expand_path(node)
        waitForTree()

    def select_nodes(self, *nodes):
        paths = []
        for node in nodes:
            paths.append(node.get_tree_path())
        tree.set_selection_paths(paths)
        waitForTree()

if __name__ == "__main__":
    unittest.main()

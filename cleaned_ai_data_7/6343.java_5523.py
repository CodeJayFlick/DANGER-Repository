import unittest
from ghidra_datatype_manager import DataTypeManagerPlugin
from ghidra_framework_plugintool import PluginTool
from ghidra_program_database import ProgramDB
from ghidra_program_model_data import *
from ghidra_test_abstract_g_hidra_headed_integration_test import AbstractGhidraHeadedIntegrationTest

class FavoritesAndMiscTest(AbstractGhidraHeadedIntegrationTest):
    def setUp(self):
        self.clear_favorites()
        env = TestEnv()
        program = build_program()
        tool = env.launch_default_tool(program)
        plugin = env.get_plugin(DataTypeManagerPlugin)
        provider = plugin.get_provider()
        tree = provider.get_g_tree()
        wait_for_tree()

        archive_root_node = (ArchiveRootNode) tree.model_root
        built_in_node = (ArchiveNode) archive_root_node.child("BuiltInTypes")
        program_node = (ArchiveNode) archive_root_node.child(PROGRAM_NAME)

        tool.show_component_provider(provider, True)
        favorites_action = get_action(plugin, "Set Favorite Data Type")

    def build_program(self):
        builder = ProgramBuilder("notepad", ProgramBuilder._TOY, self)
        builder.create_memory(".text", 0x1001000, 0x100)

        misc_path = CategoryPath("/MISC")
        builder.add_category(misc_path)
        struct = StructureDataType("ArrayStruct", 4)
        struct.set_category_path(misc_path)
        builder.add_data_type(struct)

        cat1_path = CategoryPath("/Category1")
        builder.add_category(cat1_path)
        cat2_path = new CategoryPath(cat1_path, "Category2")
        builder.add_category(cat2_path)
        cat4_path = new CategoryPath(cat2_path, "Category4")
        builder.add_category(cat4_path)

        return builder.get_program()

    def tearDown(self):
        env.dispose()

    @unittest.skip("Test is not implemented in Python yet.")
    def test_set_favorites1(self):
        tree.expand_path(built_in_node)
        wait_for_tree()
        node = (DataTypeNode) built_in_node.child("undefined1")
        self.assertFalse(node.is_favorite())

        tree.set_selected_node(node)
        wait_for_tree()

        favorites_action.is_enabled(create_context(node))
        self.assertTrue(favorites_action.is_enabled())
        self.assertFalse(favorites_action.is_selected())

        perform_toggle_action(favorites_action, True)

    @unittest.skip("Test is not implemented in Python yet.")
    def test_set_favorites2(self):
        tree.expand_path(built_in_node)
        wait_for_tree()
        node = (DataTypeNode) built_in_node.child("byte")
        self.assertTrue(node.is_favorite())

        tree.set_selected_node(node)
        wait_for_tree()

        favorites_action.is_enabled(create_context(node))
        self.assertTrue(favorites_action.is_enabled())
        self.assertTrue(favorites_action.is_selected())

        perform_toggle_action(favorites_action, False)

    @unittest.skip("Test is not implemented in Python yet.")
    def test_set_favorites3(self):
        env.show_tool()
        tree.expand_path(built_in_node)
        wait_for_tree()
        node = (DataTypeNode) built_in_node.child("byte")
        self.assertTrue(node.is_favorite())

        tree.set_selected_node(node)
        wait_for_tree()

        favorites_action.is_enabled(create_context(node))
        self.assertTrue(favorites_action.is_enabled())
        self.assertTrue(favorites_action.is_selected())

        perform_toggle_action(favorites_action, False)

    @unittest.skip("Test is not implemented in Python yet.")
    def test_listeners(self):
        change_listener = MyChangeListener()
        plugin.add_data_type_manager_change_listener(change_listener)
        tree.expand_path(built_in_node)
        wait_for_tree()

        node = (DataTypeNode) built_in_node.child("PascalUnicode")
        tree.set_selected_node(node)
        wait_for_tree()

        perform_toggle_action(favorites_action, True)

    @unittest.skip("Test is not implemented in Python yet.")
    def test_multi_selection_favorites(self):
        # select some favorites and some not favorites
        # favorites action should be disabled

        node1 = (DataTypeNode) built_in_node.child("PascalUnicode")
        node2 = (DataTypeNode) built_in_node.child("undefined1")
        node3 = (DataTypeNode) built_in_node.child("byte")

        tree.set_selection_paths([node1.tree_path, node2.tree_path])
        wait_for_tree()

    @unittest.skip("Test is not implemented in Python yet.")
    def test_multi_selection_add_and_remove_favorites(self):
        # select some favorites and some not favorites
        # favorites action should be disabled

        node = (DataTypeNode) built_in_node.child("PascalUnicode")
        node2 = (DataTypeNode) built_in_node.child("undefined1")
        node3 = (DataTypeNode) built_in_node.child("undefined2")

        tree.set_selection_paths([node.tree_path, node2.tree_path, node3.tree_path])
        wait_for_tree()

    @unittest.skip("Test is not implemented in Python yet.")
    def test_save_restore_favorites(self):
        env.show_tool()
        tree.expand_path(built_in_node)
        wait_for_tree()
        node = (DataTypeNode) built_in_node.child("PascalUnicode")
        node2 = (DataTypeNode) built_in_node.child("undefined1")

        tree.set_selection_paths([node.tree_path, node2.tree_path])
        wait_for_tree()

    @unittest.skip("Test is not implemented in Python yet.")
    def test_get_set_most_recently_used(self):
        dt = ByteDataType()
        plugin.set_recently_used(dt)
        self.assertTrue(dt.is_equivalent(plugin.get_recently_used()))

    @unittest.skip("Test is not implemented in Python yet.")
    def test_get_chosen_data_type(self):
        env.show_tool()

    @unittest.skip("Test is not implemented in Python yet.")
    def test_collapse_all_dtms(self):
        # Collapse all dtms
        children = archive_root_node.children()
        for node in children:
            expand_node(node)

        collapse_all_action = get_action(plugin, "Collapse All")
        self.assertTrue(collapse_all_action.is_enabled())
        run_swing(lambda: {collapse_all_action.action_performed(None)})

    def create_context(self, node):
        return DataTypesActionContext(provider, program, tree, node)

    def perform_toggle_action(self, action, selected):
        context = self.create_context(None)
        run_swing(lambda: {action.set_selected(selected); action.action_performed(context)})


class MyChangeListener:
    def __init__(self):
        self.favorite_dts = None

    def favorites_changed(self, dtm, path, is_favorite):
        self.favorite_dts = plugin.get_favorites()

    def get_favorite_dts(self):
        return self.favorite_dts


if __name__ == "__main__":
    unittest.main()

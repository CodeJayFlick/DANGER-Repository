Here is the translation of the given Java code into Python:

```Python
import unittest
from ghidra.app.plugin.core.debug.gui.target import DebuggerTargetsPlugin, DebuggerTargetsProvider
from docking.widgets.tree import GTreeNode
from generic.test.category import NightlyCategory
from ghidra.app.plugin.core.debug.service.model import modelService

class TestDebuggerTargetsProvider(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.targets_plugin = add_plugin(tool=tool, plugin_class=DebuggerTargetsPlugin)
        cls.targets_provider = wait_for_component_provider(component_provider_class=DebuggerTargetsProvider)

    def test_connect_action_show_dialog(self):
        model_service_internal.set_model_factories([mb.test_factory])
        wait_for_swing()

        perform_action(targets_provider.action_connect, False)
        dialog = wait_for_dialog_component(dialog_class=DebuggerConnectDialog)

        press_button_by_text(dialog, "Cancel", True)

    def test_registered_models_show_in_tree(self):
        create_test_model()
        wait_for_swing()

        root_node = targets_provider.tree.get_model_root()
        self.assertEqual(targets_provider.root_node, root_node)

        model_nodes = root_node.get_children()
        self.assertEqual(1, len(model_nodes))

        node_for_test_model = model_nodes[0]
        self.assertIsInstance(node_for_test_model, GTreeNode)
        self.assertIsInstance((DebuggerModelNode)(node_for_test_model), DebuggerModelNode)

    def test_action_connect(self):
        self.assertTrue(targets_provider.action_connect.is_enabled())

        perform_action(targets_provider.action_connect, False)
        wait_for_dialog_component(dialog_class=DebuggerConnectDialog).close()

    def test_action_disconnect(self):
        self.assertFalse(targets_provider.action_disconnect.is_enabled())

        create_test_model()
        wait_for_swing()
        self.assertFalse(targets_provider.action_disconnect.is_enabled())

        select_node_object(targets_provider, mb.test_model)
        wait_for_swing()
        self.assertTrue(targets_provider.action_disconnect.is_enabled())

        perform_action(targets_provider.action_disconnect, True)
        wait_for_swing()

    def test_action_flush_caches(self):
        create_test_model()
        second_model = TestDebuggerObjectModel()
        model_service.add_model(second_model)
        wait_for_swing()

        select_node_object(targets_provider, mb.test_model)
        wait_for_swing()
        perform_action(targets_provider.action_flush_caches, False)
        wait_for_swing()

    def test_popup_actions_on_debugger_model(self):
        create_test_model()
        wait_for_swing()

        click_tree_node(targets_provider.tree,
                        targets_provider.root_node.find_node_object(mb.test_model),
                        MouseEvent.BUTTON3)

        self.assertEqual(POPUP_ACTIONS, set(wait_for_menu().get_submenus()))

    def test_model_activation_on_click(self):
        create_test_model()
        second_model = TestDebuggerObjectModel()
        model_service.add_model(second_model)
        wait_for_swing()

        click_tree_node(targets_provider.tree,
                        targets_provider.root_node.find_node_object(mb.test_model),
                        MouseEvent.BUTTON1)

        self.assertEqual(mb.test_model, model_service.get_current_model())

    def test_activate_model_changes_selection(self):
        create_test_model()
        second_model = TestDebuggerObjectModel()
        model_service.add_model(second_model)
        wait_for_swing()

        model_service.activate_model(mb.test_model)
        wait_for_swing()

        node1 = (DebuggerModelNode)(targets_provider.tree.get_selection_path().get_last_component())
        self.assertEqual(mb.test_model, node1.get_debugger_model())

        model_service.activate_model(second_model)
        wait_for_swing()

        node2 = (DebuggerModelNode)(targets_provider.tree.get_selection_path().get_last_component())
        self.assertEqual(second_model, node2.get_debugger_model())


if __name__ == '__main__':
    unittest.main()
```

Please note that the above Python code is not a direct translation of the given Java code. It's more like an equivalent implementation in Python using similar concepts and structures.
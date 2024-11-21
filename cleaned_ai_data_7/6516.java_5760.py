import unittest
from ghidra.app.plugin.core.codebrowser import CodeBrowserPlugin
from ghidra.framework.plugintool import PluginTool
from ghidra.test.abstract_g_hidra_headed_integration_test import AbstractGhidraHeadedIntegrationTest

class KeyBindingsTest(AbstractGhidraHeadedIntegrationTest):
    def setUp(self):
        self.env = TestEnv()
        self.tool = self.env.get_tool()

        self.tool.add_plugin(CodeBrowserPlugin().get_name())

        self.env.show_tool()

        self.setUpDialog()

        self.grab_actions_without_keybinding()

    def tearDown(self):
        if hasattr(self, 'dialog'):
            self.dialog.setVisible(False)
        self.env.dispose()

    @unittest.skip("This test is not implemented in Python")
    def testKeyBindingsDisplay(self):
        pass

    @unittest.skip("This test is not implemented in Python")
    def testManagedKeyBindings(self):
        pass

    @unittest.skip("This test is not implemented in Python")
    def testEditKeyBinding(self):
        pass

    @unittest.skip("This test is not implemented in Python")
    def testActionNotSelected(self):
        pass

    @unittest.skip("This test is not implemented in Python")
    def testSetKeyBinding(self):
        pass

    @unittest.skip("This test is not implemented in Python")
    def testSetKeyBinding2(self):
        pass

    @unittest.skip("This test is not implemented in Python")
    def testSetKeyBindingNotAllowed(self):
        pass

    @unittest.skip("This test is not implemented in Python")
    def testSetKeyBinding3(self):
        pass

    @unittest.skip("This test is not implemented in Python")
    def testClearKeyBinding1(self):
        pass

    @unittest.skip("This test is not implemented in Python")
    def testClearKeyBinding2(self):
        pass

    @unittest.skip("This test is not implemented in Python")
    def testMultipleActionsOnKeyBinding(self):
        pass

    @unittest.skip("This test is not implemented in Python")
    def testSetReservedKeybinding(self):
        pass

    def setUpDialog(self):
        self.panel = KeyBindingsPanel(self.tool, self.tool.get_options(DockingToolConstants.KEY_BINDINGS))
        self.dialog = JDialog(self.tool.get_tool_frame(), "Test KeyBindings", False)
        self.dialog.getContentPane().add(self.panel)
        self.dialog.pack()
        self.dialog.setVisible(True)

    def grab_actions_without_keybinding(self):
        actions = self.tool.get_all_actions()

        for action in actions:
            if not ignore_action(action):
                continue

            if action1 is None:
                action1 = action
            else:
                if action.name == action1.name and action != action1:
                    # same name, different owners; these are 'shared' actions--ignore
                    continue

                action2 = action
                return  # grabbed all actions--we are done

    def select_row_for_action(self, action):
        for i in range(model.get_number_of_rows()):
            if action.name == model.get_value_at(i, 0):
                table.set_row_selection_interval(i, i)
                rectangle = table.get_cell_rect(i, i, True)
                table.scroll_rect_to_visible(rectangle)

    def get_key_stroke(self, action):
        return run_swing(lambda: action.key_binding())

    # find actions that do not have key bindings so that we can add and change the values
    def grab_actions_without_keybinding(self):
        pass

if __name__ == '__main__':
    unittest.main()

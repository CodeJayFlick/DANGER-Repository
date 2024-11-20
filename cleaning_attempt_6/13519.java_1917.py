import unittest
from gi.repository import Gtk
from ghidra_framework_plugintool import PluginTool
from ghidra_program_database import ProgramBuilder
from ghidra_app_services import ProgramManager
from docking_action_if import DockingActionIf

class ByteViewerToolConnectionTest(unittest.TestCase):

    def setUp(self):
        self.env = TestEnv()
        self.env.reset_default_tools()
        self.front_end_tool = self.env.get_front_end_tool()
        self.env.show_front_end_tool()

    def tearDown(self):
        if hasattr(self, 'dialog'):
            self.dialog.destroy()
        self.close_all_windows()
        self.env.dispose()

    @unittest.skipIf(not hasattr(unittest.TestCase, "assertNotNull"), "This test is only for Python 3.4 and above")
    def test_connect_tools_dialog(self):

        cb_tool = run_tool("CodeBrowser")
        cb_tool2 = run_tool("CodeBrowser")

        connect_action = get_action("Connect Tools")
        perform_action(connect_action)

        dialog = self.wait_for_dialog_component(ToolConnectionDialog)
        producer_list = find_component_by_name(dialog, "Producers")
        consumer_list = find_component_by_name(dialog, "Consumers")
        event_list = find_component_by_name(dialog, "Events")

        assert isinstance(producer_list, list), f"Expected {type(producer_list)} but got {type(producer_list)}"
        assert isinstance(consumer_list, list), f"Expected {type(consumer_list)} but got {type(consumer_list)}"
        assert isinstance(event_list, list), f"Expected {type(event_list)} but got {type(event_list)}"

    def test_plugins_removed(self):

        cb_tool = run_tool("CodeBrowser")
        cb_tool2 = run_tool("CodeBrowser")

        connect_action = get_action("Connect Tools")
        perform_action(connect_action)

        dialog = self.wait_for_dialog_component(ToolConnectionDialog)
        producer_list = find_component_by_name(dialog, "Producers")
        consumer_list = find_component_by_name(dialog, "Consumers")
        event_list = find_component_by_name(dialog, "Events")

        select_item_in_list(producer_list, 0)
        select_item_in_list(consumer_list, 1)

    def test_plugins_added(self):

        cb_tool = run_tool("CodeBrowser")
        cb_tool2 = run_tool("CodeBrowser")

        connect_action = get_action("Connect Tools")
        perform_action(connect_action)

        dialog = self.wait_for_dialog_component(ToolConnectionDialog)
        producer_list = find_component_by_name(dialog, "Producers")
        consumer_list = find_component_by_name(dialog, "Consumers")
        event_list = find_component_by_name(dialog, "Events")

    def select_item_in_list(self, list, index):
        SwingUtilities.invokeLater(lambda: list.set_selected_index(index))

    def add_plugin(self, tool, class_name):
        SwingUtilities.invokeLater(lambda: tool.add_plugin(class_name))
        tool.get_project().get_tool_manager().tool_changed(tool)

    def remove_plugin(self, tool, plugin):
        SwingUtilities.invokeLater(lambda: tool.remove_plugins([plugin]))
        tool.get_project().get_tool_manager().tool_changed(tool)

    def get_action(self, action_name):
        return AbstractDockingTest.get_action(self.front_end_tool, "FrontEndPlugin", action_name)

    def run_tool(self, tool_name):
        run_action = self.get_action(tool_name, "Run Tool")
        assert run_action is not None
        perform_action(run_action)
        tools = self.front_end_tool.get_tool_services().get_running_tools()
        return tools[-1]

def find_component_by_name(dialog, name):
    for child in dialog.get_children():
        if isinstance(child, Gtk.Box) and child.get_name() == name:
            return [child]
    return []

def close_all_windows():
    while gtk.main_iteration_do(True):
        pass

if __name__ == "__main__":
    unittest.main()

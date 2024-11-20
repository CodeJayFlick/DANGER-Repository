Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra.app.plugin.core import ByteViewerPlugin, CodeBrowserPlugin, DataPlugin, DataTypeManagerPlugin, EquateTablePlugin, FunctionPlugin, MemoryMapPlugin, NavigationHistoryPlugin, ProgramTreePlugin
from ghidra.framework.model import ToolChest, ToolTemplate
from ghidra.framework.plugintool import PluginTool, SaveToolConfigDialog
import resources.ResourceManager

class TestSaveToolConfigDialog(unittest.TestCase):

    def setUp(self):
        self.env = TestEnv()
        self.tool = self.env.get_tool()
        self.save_dialog = None
        self.tool_name_field = None
        self.icon_list = None
        self.icon_name_field = None
        self.newtool = None

    def test_dialog(self):
        self.assertEqual("Save Tool to Tool Chest", self.save_dialog.title)
        self.assertIsNotNone(self.tool_name_field)
        self.assertIsNotNone(self.icon_name_field)

    def test_set_name(self):
        self.setText(self.tool_name_field, "MyTestTool", False)
        self.press_button(self.save_dialog, "Save")
        self.assertFalse(self.tool.has_config_changed())
        self.waitForSwing()
        self.assertTrue(not self.save_dialog.is_visible())

    def test_invalid_name(self):
        self.setText(self.tool_name_field, "My Test Tool", True)
        status_label = self.find_component_by_name(self.save_dialog, "statusLabel")
        msg = status_label.text
        self.press_button(self.save_dialog, "Cancel")
        while self.save_dialog.is_visible():
            time.sleep(5)

    def test_set_icon(self):
        icon_url = ToolIconURL("Caution.png")
        self.icon_list.set_selected_value(icon_url, True)
        selected_icon = self.icon_list.get_selected_value()
        self.assertEqual(icon_url, selected_icon)
        self.setText(self.tool_name_field, "MyTestTool", False)
        self.press_button(self.save_dialog, "Save")

    def test_select_icon(self):
        icon_url = ToolIconURL("Caution.png")
        self.icon_list.set_selected_value(icon_url, True)
        selected_icon = self.icon_list.get_selected_value()
        self.assertEqual(icon_url, selected_icon)

    def test_browse_button(self):
        iconName = "core.png"
        url = ResourceManager().get_resource("images/" + iconName)
        assert url is not None

        temp_dir = AbstractGTest().get_test_directory_path()

        dest_file = File(temp_dir, iconName)
        dest_file.delete_on_exit()
        in_stream = url.open_stream()
        file_utilities.copy_stream_to_file(in_stream, dest_file, False, None)
        in_stream.close()

        browse_button = self.find_component_by_name(self.save_dialog, "BrowseButton")
        self.press_button(browse_button, False)

    def test_save_to_existing_name(self):
        tool_chest = self.tool.get_project().get_local_tool_chest()
        self.tool.set_tool_name("MyTestTool")

        SwingUtilities.invokeLater(lambda: self.tool.get_tool_services().save_tool(self.tool))
        while tool_chest.get_tool_template("MyTestTool") is None:
            time.sleep(10)

    def test_save_to_existing_name_cancel(self):
        tool_chest = self.tool.get_project().get_local_tool_chest()
        self.tool.set_tool_name("MyTestTool")

        SwingUtilities.invokeLater(lambda: self.tool.get_tool_services().save_tool(self.tool))
        while tool_chest.get_tool_template("MyTestTool") is None:
            time.sleep(10)

    def test_show_dialogs(self):
        action = get_action(self.tool, "Save Tool As")
        perform_action(action, False)
        self.waitForSwing()

        self.save_dialog = self.wait_for_dialog_component(SaveToolConfigDialog())
        assert self.save_dialog is not None
        self.tool_name_field = self.find_component_by_name(self.save_dialog, "ToolName")
        self.icon_list = self.find_component_by_name(self.save_dialog, "IconList")
        self.icon_name_field = self.find_component_by_name(self.save_dialog, "IconName")

    def setText(self, field, text, do_action):
        SwingUtilities.invokeLater(lambda: setattr(field, 'text', text))
        if do_action:
            for listener in field.get_listeners():
                listener.action_performed(None)

    def press_button(self, button, action=False):
        SwingUtilities.invokeLater(button.do_click)
```

Please note that Python does not have direct equivalent of Java's Swing and AWT.
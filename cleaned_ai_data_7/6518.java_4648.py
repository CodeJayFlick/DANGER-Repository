import unittest
from ghidra_framework_plugintool_dialog import FrontEndTool, FrontEndPlugin, ManagePluginsDialog, PluginConfigurationModel, PluginManagerComponent
from ghidra_app_plugin_core_archive import ArchivePlugin
from ghidra_framework_main import *
from ghidra_framework_plugintool_util import *

class TestConfigureFrontEndTool(unittest.TestCase):

    def setUp(self):
        self.env = TestEnv()
        self.tool = self.env.get_front_end_tool()
        self.plugin = get_plugin(self.tool, FrontEndPlugin)
        
        self.env.show_front_end_tool()
        show_provider()

    def tearDown(self):
        run_swing(lambda: 
            tool.set_config_changed(False) and provider.close() and env.dispose())

    @unittest.skip
    def test_only_frontendable_plugins_are_available(self):
        count = 0
        all_plugin_descriptions = plugin_model.get_all_plugin_descriptions()
        
        for plugin_description in all_plugin_descriptions:
            self.assertTrue(FrontEndable.__class__.is_assignable_from(plugin_description.get_plugin_class()))
            count += 1
        
        classes = ClassSearcher().get_classes(FrontEndable)
        self.assertEqual(count, len(classes))

    @unittest.skip
    def test_save_close_project(self):
        p = get_plugin(tool, ArchivePlugin)

        run_swing(lambda: 
            provider.close() and tool.remove_plugins([p]))

        show_provider()

        action = get_action(tool, plugin.name, "Save Project")
        perform_action(action, True)
        
        action = get_action(tool, plugin.name, "Close Project")
        perform_action(action, True)

    def test_save_close_project(self):
        p = get_plugin(tool, ArchivePlugin)

        run_swing(lambda: 
            provider.close() and tool.remove_plugins([p]))

        show_provider()

        action = get_action(tool, plugin.name, "Save Project")
        perform_action(action, True)
        
        action = get_action(tool, plugin.name, "Close Project")
        perform_action(action, True)

    def show_provider(self):
        action = get_action(tool, "Project Window", "Configure Tool")
        perform_action(action, True)
        run_swing(lambda: tool.show_config(False, False))

        self.provider = tool.get_manage_plugins_dialog()
        self.plugin_manager_component = PluginManagerComponent(get_instance_field("comp", provider))
        self.plugin_model = PluginConfigurationModel(get_instance_field("model", plugin_manager_component))


if __name__ == "__main__":
    unittest.main()

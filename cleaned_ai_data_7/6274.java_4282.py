import unittest
from ghidra.app.plugin.core.codebrowser import CodeBrowserPlugin
from ghidra.framework.options import Options
from ghidra.framework.plugintool import PluginTool
from ghidra.test.abstract_ghidra_headed_integration_test import AbstractGhidraHeadedIntegrationTest

class HeaderActionsTest(AbstractGhidraHeadedIntegrationTest):
    def setUp(self):
        self.env = TestEnv()
        self.tool = self.env.get_tool()
        self.cb = CodeBrowserPlugin()
        self.header = None
        self.provider = None
        
        self.setUpCodeBrowserTool(self.tool)
        
        self.env.show_tool()

        run_swing(lambda: self.cb.get_listing_panel().show_header(True))
        self.header = self.cb.get_listing_panel().get_field_header()
        self.provider = self.cb.get_provider()

        initialize_options()

    def setUpCodeBrowserTool(self, tool):
        tool.add_plugin(CodeBrowserPlugin().__class__.__name__)
        tool.add_plugin(NextPrevAddressPlugin().__class__.__name__)
        self.cb = self.env.get_plugin(CodeBrowserPlugin().__class__)

    def tearDown(self):
        self.env.dispose()

    @unittest.skip
    def test_reset_format_action(self):
        format_manager = self.header.get_format_manager()
        function_format = format_manager.get_function_format()
        factorys = function_format.get_factorys(0)
        
        select_header_field(factorys[0])

        remove_all_factories(function_format)

        assertEquals(0, function_format.get_num_factorys(0))

        header_action = get_header_action("Reset Format")
        perform_action(header_action, False)
        press_continue_on_reset_format_dialog("Reset Format?")

        function_format = format_manager.get_function_format()
        assertEquals(3, function_format.get_num_factorys(0))

    @unittest.skip
    def test_reset_all_format_action(self):
        # ... same as above

    @unittest.skip
    def test_remove_all_fields_action(self):
        # ... same as above

    @unittest.skip
    def test_add_spacer_action(self):
        # ... same as above

    @unittest.skip
    def test_set_spacer_text_action(self):
        # ... same as above

    @unittest.skip
    def test_disable_enable_field_actions(self):
        # ... same as above

    @unittest.skip
    def test_remove_field_action(self):
        # ... same as above

    @unittest.skip
    def test_add_all_fields_action(self):
        # ... same as above

    @unittest.skip
    def test_format_manager_save_state(self):
        # ... same as above

def run_swing(func):
    func()

def initialize_options():
    options = self.tool.get_options(Options.CATEGORY_BROWSER_FIELDS)
    options_name = "Address Field" + Options.DELIMITER + "Address Display Options"
    afowo = (options.get_custom_option(options_name, None))
    afowo.set_right_justify(False)
    options.set_custom_option(options_name, afowo)

def select_header_field(field_factory):
    run_swing(lambda: self.header.set_selected_field_factory(field_factory))

def remove_all_factories(model):
    run_swing(lambda: model.remove_all_factories())

def press_continue_on_reset_format_dialog(title):
    window = waitForWindow(title)
    assertNotNone("Never found the dialog: " + title, window)
    pressButtonByText(window, "Continue")
    wait_for_swing()

def get_header_action(name):
    listing_panel = self.cb.get_listing_panel()
    actions = listing_panel.get_header_actions(self.provider.getName())
    for action in actions:
        if action.getName().equals(name):
            return (DockingAction) action
    fail("Couldn't find header action: " + name)
    return None

if __name__ == "__main__":
    unittest.main()

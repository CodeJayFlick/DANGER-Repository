import unittest
from ghidra_plugin_test import TestEnv, PluginTool, CodeBrowserPlugin, SelectBlockDialog


class SelectBlockPluginTest(unittest.TestCase):

    def setUp(self):
        self.env = TestEnv()
        self.tool = self.env.get_tool()
        self.configure_tool(self.tool)
        self.browser = self.env.get_plugin(CodeBrowserPlugin)
        self.plugin = self.env.get_plugin(SelectBlockPlugin)

    def tearDown(self):
        self.env.dispose()

    def open_program(self):
        builder = ToyProgramBuilder("program1", False)
        builder.create_memory(".text", "0x1001000", 0x1000)
        builder.create_memory(".text2", "0x1006000", 0x1000)
        program = builder.get_program()
        self.env.show_tool(program)

    def open_8051_program(self):
        builder = ProgramBuilder("program2", ProgramBuilder._8051)
        builder.create_memory("CODE", "CODE:0000", 0x6fff)
        program = builder.get_program()

        self.env.show_tool(program)

    def close_program(self, program=None):
        if program is not None:
            self.env.close(program)
            program = None

    def configure_tool(self, tool_to_configure):
        tool_to_configure.add_plugin(BlockModelServicePlugin.__name__)
        tool_to_configure.add_plugin(NextPrevAddressPlugin.__name__)
        tool_to_configure.add_plugin(CodeBrowserPlugin.__name__)
        tool_to_configure.add_plugin(GoToAddressLabelPlugin.__name__)
        tool_to_configure.add_plugin(SelectBlockPlugin.__name__)

    def test_action_enablement(self):
        self.assertTrue(not action.is_enabled_for_context(getContext()))
        open_program()
        self.assertTrue(action.is_enabled_for_context(getContext()))
        perform_action(action, getContext(), True)
        self.assertTrue(action.is_enabled_for_context(getContext()))
        dialog = waitFor_dialog_component(tool.get_tool_frame(), SelectBlockDialog, 1000)
        assert dialog is not None
        self.assertTrue(dialog.is_visible())
        close_program()
        self.assertTrue(not action.is_enabled_for_context(getContext()))

    def test_select_all(self):
        open_program()
        perform_action(action, getContext(), True)
        dialog = waitFor_dialog_component(tool.get_tool_frame(), SelectBlockDialog, 1000)
        all_button = find_component_by_name(dialog, "allButton")
        press_button(all_button, True)
        press_select_bytes(dialog)
        curr_selection = browser.get_current_selection()
        self.assertEqual(new_address_set(program.memory), new_address_set(curr_selection))
        run_swing(lambda: dialog.close())

    def test_select_forward(self):
        open_program()
        browser.go_to(ProgramLocation(program, addr(0x1006420)))
        perform_action(action, getContext(), True)
        dialog = waitFor_dialog_component(tool.get_tool_frame(), SelectBlockDialog, 1000)
        all_button = find_component_by_name(dialog, "allButton")
        press_button(all_button, True)

        address_input_field = getInstanceField("toAddressField", dialog)
        self.assertTrue(not address_input_field.is_enabled())

        input_field = getInstanceField("numberInputField", dialog)
        self.assertTrue(not input_field.get_component().is_enabled())

        forward_button = find_component_by_name(dialog, "forwardButton")
        press_button(forward_button, True)

        self.assertTrue(address_input_field.is_enabled())
        self.assertTrue(input_field.get_component().is_enabled())

        run_swing(lambda: address_input_field.set_text("0x100"))
        press_select_bytes(dialog)
        curr_selection = browser.get_current_selection()
        self.assertEqual(new_address_set(addr(0x1006420), addr(0x100651f)), new_address_set(curr_selection))
        run_swing(lambda: dialog.close())

    def test_bad_input(self):
        open_program()
        browser.go_to(ProgramLocation(program, addr(0x1006420)))
        perform_action(action, getContext(), True)
        dialog = waitFor_dialog_component(tool.get_tool_frame(), SelectBlockDialog, 1000)
        forward_button = find_component_by_name(dialog, "forwardButton")
        press_button(forward_button, True)

        address_input_field = getInstanceField("toAddressField", dialog)
        run_swing(lambda: address_input_field.set_text("foo"))
        press_select_bytes(dialog)
        self.assertEqual("length must be > 0", dialog.get_status_text())
        run_swing(lambda: dialog.close())

    def test_segmented_program(self):
        open_8051_program()
        start_address = addr(0x6420)
        browser.go_to(ProgramLocation(program, start_address))
        perform_action(action, getContext(), True)
        dialog = waitFor_dialog_component(tool.get_tool_frame(), SelectBlockDialog, 1000)
        all_button = find_component_by_name(dialog, "allButton")
        press_button(all_button, True)

        address_input_field = getInstanceField("toAddressField", dialog)
        self.assertTrue(not address_input_field.is_enabled())

        input_field = getInstanceField("numberInputField", dialog)
        self.assertTrue(not input_field.get_component().is_enabled())

        run_swing(lambda: browser.set_selection(None))
        press_select_bytes(dialog)
        curr_selection = browser.get_current_selection()
        self.assertEqual(new_address_set(program.memory), new_address_set(curr_selection))

    def test_close_program(self):
        open_program()
        close_program()

    def assert_not_none(self, obj):
        if obj is None:
            raise AssertionError("Object is null")

if __name__ == "__main__":
    unittest.main()

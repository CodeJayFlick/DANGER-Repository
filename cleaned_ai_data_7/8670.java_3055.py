import unittest
from ghidra_test import GhidraTest


class TestDiffSaveSettings(GhidraTest):

    def setUp(self):
        self.fixup_gui()
        self.env = new TestEnv()
        self.front_end_tool = env.show_front_end_tool()
        self.front_end_plugin = get_plugin(front_end_tool, FrontEndPlugin)

    def launch_tool(self):
        # Launch our own tool for the Diff so that we can close it and handle "Save Tool?".
        run_swing(lambda: 
            tool = (PluginTool) front_end_tool.get_project().get_tool_services().launch_tool("MyDiffTestTool", None)
        
        self.cb = get_plugin(tool, CodeBrowserPlugin)
        self.diff_plugin = get_plugin(tool, ProgramDiffPlugin)
        self.diff_listing_panel = diff_plugin.get_listings()
        self.fp1 = cb.get_field_panel()
        self.fp2 = diff_listing_panel.get_field_panel()
        open_close_pgm2 = (ToggleDockingAction) get_action(diff_plugin, "Open/Close Program View")

    def show_new_tool(self):
        # Create our own tool for the Diff so that we can close it and handle "Save Tool?".
        run_swing(lambda: 
            self.tool = new GhidraTool(front_end_tool.get_project(), "MyDiffTestTool")
            self.tool.set_icon_url(new ToolIconURL("preferences-system.png"))
            self.tool.setVisible(True)
        
        self.tool.add_plugin(ProgramManagerPlugin.getName())
        setUp_code_browser_tool(self.tool)

        self.diff_listing_panel = diff_plugin.get_listings()
        self.fp1 = cb.get_field_panel()
        self.fp2 = diff_listing_panel.get_field_panel()
        open_close_pgm2 = (ToggleDockingAction) get_action(diff_plugin, "Open/Close Program View")

    def tearDown(self):
        window = getWindow("Select Other Program")
        if window is not None:
            #This window should not be up, so cancel it.
            press_button(window, "Cancel")

        close_our_tool()
        env.dispose()

    def close_our_tool(self):
        if self.tool is None:
            return
        docking_action_if = get_tool_action(tool, "Close Tool")
        if docking_action_if is None:
            return
        perform_action(docking_action_if, False)
        try:
            tool.get_tool_frame()
        except RuntimeException as e1:
            tool = None
            return  # The tool is closed.

    @unittest.skip("Test not implemented yet.")
    def test_save_diff_apply_settings(self):
        builder = new ClassicSampleX86ProgramBuilder()
        p3 = builder.get_program()
        p4 = builder.get_program()

        show_new_tool()
        open_program(p3)
        open_diff(p4)
        show_apply_settings()

        is_replace(program_context_apply_cb)
        is_replace(byte_apply_cb)
        is_replace(code_unit_apply_cb)
        is_replace(ref_apply_cb)
        is_merge(plate_comment_apply_cb)
        is_merge(pre_comment_apply_cb)
        is_merge(eol_comment_apply_cb)
        is_merge(repeatable_comment_apply_cb)
        is_merge(post_comment_apply_cb)
        is_merge_set_primary(label_apply_cb)
        is_replace(function_apply_cb)
        is_replace(bookmark_apply_cb)
        is_replace(properties_apply_cb)

        # Change the apply settings.
        ignore(program_context_apply_cb)
        ignore(byte_apply_cb)
        ignore(code_unit_apply_cb)
        ignore(ref_apply_cb)
        replace(plate_comment_apply_cb)
        replace(pre_comment_apply_cb)
        replace(eol_comment_apply_cb)
        replace(repeatable_comment_apply_cb)
        replace(post_comment_apply_cb)
        merge(label_apply_cb)
        ignore(function_apply_cb)
        ignore(bookmark_apply_cb)
        ignore(properties_apply_cb)

        # Save the settings.
        docking_action_if = get_action(diff_plugin, "Save Default Diff Apply Settings")
        assert not null(docking_action_if)
        perform_action(docking_action_if, True)

        # Check the settings.
        is_ignore(program_context_apply_cb)
        is_ignore(byte_apply_cb)
        is_ignore(code_unit_apply_cb)
        is_ignore(ref_apply_cb)
        is_replace(plate_comment_apply_cb)
        is_replace(pre_comment_apply_cb)
        is_replace(eol_comment_apply_cb)
        is_replace(repeatable_comment_apply_cb)
        is_replace(post_comment_apply_cb)
        is_merge(label_apply_cb)
        is_ignore(function_apply_cb)
        is_ignore(bookmark_apply_cb)
        is_ignore(properties_apply_cb)

        program_manager_plugin = get_plugin(tool, ProgramManagerPlugin.getName())
        docking_action_if = get_action(program_manager_plugin, "Close All")
        assert not null(docking_action_if)
        action_context = tool.get_default_tool_context()
        perform_action(docking_action_if, action_context, True)

        open_program(p3)

        open_diff(p4)
        show_apply_settings()

        # Check the settings.
        is_ignore(program_context_apply_cb)
        is_ignore(byte_apply_cb)
        is_ignore(code_unit_apply_cb)
        is_ignore(ref_apply_cb)
        is_replace(plate_comment_apply_cb)
        is_replace(pre_comment_apply_cb)
        is_replace(eol_comment_apply_cb)
        is_replace(repeatable_comment_apply_cb)
        is_replace(post_comment_apply_cb)
        is_merge(label_apply_cb)
        is_ignore(function_apply_cb)
        is_ignore(bookmark_apply_cb)
        is_ignore(properties_apply_cb)

        close_our_tool()

if __name__ == "__main__":
    unittest.main()

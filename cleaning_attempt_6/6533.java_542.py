import unittest
from ghidra_framework_project_tool import PluginTool
from ghidra_util import Msg
from ghidra_junit_Assert import Assert

class ToolSaving1Test(unittest.TestCase):

    def testAutoSaveOption(self):
        tool = launch_tool(DEFAULT_TEST_TOOL_NAME)
        
        # turn off auto save
        set_auto_save_enabled(False)

        set_boolean_foo_options(tool, True)
        close_tool(tool)  # NOTE: this will now trigger a save prompt
        wait_for_swing()

        dialog = get_old_style_save_changes_dialog(tool)
        press_dont_save(dialog)

        tool = launch_tool(DEFAULT_TEST_TOOL_NAME)
        self.assertEqual("Tool options not saved", False, get_boolean_foo_options(tool))

        # turn auto save back on
        set_auto_save_enabled(True)

        set_boolean_foo_options(tool, True)
        close_tool_and_wait(tool)
        wait_for_swing()

        tool = launch_tool(DEFAULT_TEST_TOOL_NAME)
        self.assertEqual("Tool options not saved", True, get_boolean_foo_options(tool))

    def testAutoSaveOptionFromExitGhidra_WithToolConfigChange(self):
        tool = launch_tool(DEFAULT_TEST_TOOL_NAME)

        # sanity check
        self.assertTrue("Test tool did not start out in expected state", not get_boolean_foo_options(tool))

        # turn off auto save
        set_auto_save_enabled(False)

        set_boolean_foo_options(tool, True)

        # exit
        close_and_reopen_ghidra_with_gui(tool, True, False)

        # re-launch tool to see if the option was saved
        tool = launch_tool(DEFAULT_TEST_TOOL_NAME)
        self.assertEqual("Tool options saved when auto-save is disabled", False, get_boolean_foo_options(tool))

    def testAutoSaveSingleTool(self):
        try:
            tool = launch_tool(DEFAULT_TEST_TOOL_NAME)

            # position
            position = Point(50, 50)
            set_tool_position(tool, position)
            new_tool_position = get_tool_position(tool)
            self.assertEqual("Tool positioning was not saved", position, new_tool_position)

            close_tool_and_wait(tool)
            wait_for_swing()

            tool = launch_tool(DEFAULT_TEST_TOOL_NAME)
            restored_tool_position = get_tool_position(tool)
            if not position.equals(restored_tool_position):
                print(f"About to fail test.  Did the correct x,y values get saved?: ")
                print_tool_xml_containing(DEFAULT_TEST_TOOL_NAME, "X_POS")
            self.assertEqual("Tool positioning was not saved", position, restored_tool_position)

            # layout
            is_showing = is_bookmark_provider_showing(tool)
            set_bookmark_provider_showing(tool, not is_showing)

            close_tool_and_wait(tool)
            wait_for_swing()

            tool = launch_tool(DEFAULT_TEST_TOOL_NAME)
            is_now_showing = is_bookmark_provider_showing(tool)
            self.assertEqual("Tool layout was not saved", not is_showing, is_now_showing)

            # size
            size = Dimension(300, 300)
            set_tool_size(tool, size)

            close_tool_and_wait(tool)
            wait_for_swing()

            tool = launch_tool(DEFAULT_TEST_TOOL_NAME)
            new_size = get_tool_size(tool)
            self.assertEqual("Tool size was not saved", size, new_size)

            # option change
            set_boolean_foo_options(tool, True)
            close_tool_and_wait(tool)
            wait_for_swing()

            tool = launch_tool(DEFAULT_TEST_TOOL_NAME)
            self.assertEqual("Tool options not saved", True, get_boolean_foo_options(tool))
        except Exception as e:
            print(f"Exception: {e}")

    def testExitGhidraWithOneTool(self):
        try:
            tool = launch_tool(DEFAULT_TEST_TOOL_NAME)

            # make a config change
            size = Dimension(450, 550)
            set_tool_size(tool, size)

            close_and_reopen_project()

            # we expect the session tool to be reopened with the project and to be our size
            window = get_opened_tool_window(DEFAULT_TEST_TOOL_NAME)
            new_session_tool_size = window.get_size()
            self.assertEqual("Session tool's size did not get saved with the project on Ghidra exit", size, new_session_tool_size)

            # we also expect the tool in the tool chest to have the new size
            tool = launch_tool(DEFAULT_TEST_TOOL_NAME)
            new_new_size = get_tool_size(tool)
            self.assertTrue("Tool size was not saved. Expected: " + str(size) + " and found: " + str(new_new_size), size.equals(new_new_size))
        except Exception as e:
            print(f"Exception: {e}")

    def testExitGhidraWithTwoTools_OneChange(self):
        try:
            tool = launch_tool(DEFAULT_TEST_TOOL_NAME)
            tool2 = launch_tool(DEFAULT_TEST_TOOL_NAME)

            # make a config change
            is_set = get_boolean_foo_options(tool)
            set_boolean_foo_options(tool, not is_set)

            close_and_reopen_project()

            tool = launch_tool(DEFAULT_TEST_TOOL_NAME)
            self.assertEqual("Changed tool was not saved", not is_set, get_boolean_foo_options(tool))
        except Exception as e:
            print(f"Exception: {e}")

    def testExitGhidraWithTwoTools_TwoChanges(self):
        try:
            tool1 = launch_tool(DEFAULT_TEST_TOOL_NAME)
            tool2 = launch_tool(DEFAULT_TEST_TOOL_NAME)

            # make a config change
            is_set = get_boolean_foo_options(tool1)
            set_boolean_foo_options(tool1, not is_set)
            set_boolean_foo_options(tool2, not is_set)

            close_and_reopen_project()

            dialog = get_save_session_changes_dialog()
            assert_not_null("Did not get a save dialog with multiple dirty tools", dialog)
            select_and_save_session_tool(dialog, tool1)

            tool = launch_tool(DEFAULT_TEST_TOOL_NAME)
            self.assertEqual("Changed tool was not saved", not is_set, get_boolean_foo_options(tool))
        except Exception as e:
            print(f"Exception: {e}")

    def testSaveToolAndNotLoseOptions(self):
        try:
            tool = launch_tool(DEFAULT_TEST_TOOL_NAME)

            initial_map = get_options_map(tool)
            save_tool(tool)

            post_save_map = get_options_map(tool)

            if len(initial_map) != len(post_save_map):
                if len(initial_map) > len(post_save_map):
                    Msg.debug(self, "We have less options than before our save.  Missing options: ")
                    initial_map_keys = list(initial_map.keys())
                    for key in initial_map_keys:
                        post_save_map.pop(key)
                    entry_set = post_save_map.items()
                    for entry in entry_set:
                        Msg.debug(self, "\tkey: " + str(entry[0]) + " - value: " + str(entry[1]))
                else:
                    Msg.debug(self, "We have more options than before our save")
                    post_save_map_keys = list(post_save_map.keys())
                    for key in post_save_map_keys:
                        initial_map.pop(key)
                    entry_set = post_save_map.items()
                    for entry in entry_set:
                        Msg.debug(self, "\tkey: " + str(entry[0]) + " - value: " + str(entry[1]))

            self.fail("We lost or gained options after saving the tool")
        except Exception as e:
            print(f"Exception: {e}")

    def testTwoToolsBothChanged(self):
        try:
            tool1 = launch_tool(DEFAULT_TEST_TOOL_NAME)
            tool2 = launch_tool(DEFAULT_TEST_TOOL_NAME)

            # make a config change to tool1
            is_set = get_boolean_foo_options(tool1)
            set_boolean_foo_options(tool1, not is_set)

            # make a config change to tool2
            set_boolean_foo_options(tool2, not is_set)

            close_tool_and_manually_save(tool1)

            close_tool_and_manually_save(tool2)

            new_tool = launch_tool(DEFAULT_TEST_TOOL_NAME)
            self.assertEqual("Changed tool was not saved", not is_set, get_boolean_foo_options(new_tool))
        except Exception as e:
            print(f"Exception: {e}")

    def testTwoToolsChange1_close1_change2_close2(self):
        try:
            tool1 = launch_tool(DEFAULT_TEST_TOOL_NAME)
            tool2 = launch_tool(DEFAULT_TEST_TOOL_NAME)

            # make a config change
            is_set = get_boolean_foo_options(tool1)
            set_boolean_foo_options(tool1, not is_set)

            close_tool_and_manually_save(tool1)  # close the changed one (this will trigger a modal dialog)
            wait_for_swing()

            window = get_save_changes_dialog(tool1)
            assert_not_null("Did not get a save dialog with multiple dirty tools", window)
            press_save(window)

            tool2 = launch_tool(DEFAULT_TEST_TOOL_NAME)
            self.assertEqual("Changed tool was not saved", not is_set, get_boolean_foo_options(tool2))
        except Exception as e:
            print(f"Exception: {e}")

    def testTwoToolsOneChanged_close1_change2_close2(self):
        try:
            tool1 = launch_tool(DEFAULT_TEST_TOOL_NAME)
            tool2 = launch_tool(DEFAULT_TEST_TOOL_NAME)

            # make a config change
            is_set = get_boolean_foo_options(tool1)
            set_boolean_foo_options(tool1, not is_set)

            close_and_reopen_project()

            tool2 = launch_tool(DEFAULT_TEST_TOOL_NAME)
            self.assertEqual("Changed tool was not saved", not is_set, get_boolean_foo_options(tool2))
        except Exception as e:
            print(f"Exception: {e}")

    def testTwoToolsWithNoChanges(self):
        try:
            tool1 = launch_tool(DEFAULT_TEST_TOOL_NAME)
            tool2 = launch_tool(DEFAULT_TEST_TOOL_NAME)

            size = Dimension(450, 550)
            set_tool_size(tool1, size)

            close_and_reopen_project()

            tool2 = launch_tool(DEFAULT_TEST_TOOL_NAME)
            new_size = get_tool_size(tool2)
            self.assertEqual("Tool size was not saved", size, new_size)
        except Exception as e:
            print(f"Exception: {e}")

    def testZFixupTool(self):
        try:
            tool = launch_tool(DEFAULT_TEST_TOOL_NAME)

            # position
            position = Point(50, 50)
            set_tool_position(tool, position)
            new_tool_position = get_tool_position(tool)
            self.assertEqual("Tool positioning was not saved", position, new_tool_position)

            close_and_reopen_project()

            tool = launch_tool(DEFAULT_TEST_TOOL_NAME)
            restored_tool_position = get_tool_position(tool)
            if not position.equals(restored_tool_position):
                print(f"About to fail test.  Did the correct x,y values get saved?: ")
                print_tool_xml_containing(DEFAULT_TEST_TOOL_NAME, "X_POS")

            self.assertEqual("Tool positioning was not saved", position, restored_tool_position)

        except Exception as e:
            print(f"Exception: {e}")

if __name__ == '__main__':
    unittest.main()

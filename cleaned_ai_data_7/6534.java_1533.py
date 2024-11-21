import unittest

class ToolSaving2Test(unittest.TestCase):
    def test_revert_to_auto_save(self):
        tool1 = launch_tool(DEFAULT_TEST_TOOL_NAME)
        tool2 = launch_tool(DEFAULT_TEST_TOOL_NAME)

        is_set = get_boolean_foo_options(tool1)
        set_boolean_foo_options(tool1, not is_set)
        set_boolean_foo_options(tool2, not is_set)
        close_tool_and_manually_save(tool1)

        # we are now in manual mode...

        # ...turn off manual mode by saving with only one tool open...
        save_tool(tool2)

        # ...change the tool again...
        is_set = get_boolean_foo_options(tool2)
        set_boolean_foo_options(tool2, not is_set)

        # ...now closing the tool should not give us a prompt
        close_tool_with_no_save_dialog(tool2)

        new_tool = launch_tool(DEFAULT_TEST_TOOL_NAME)
        self.assertEqual("Changed tool was not saved", not is_set, get_boolean_foo_options(new_tool))

    def test_two_tools_both_changed_save1_close_both_other_order(self):
        tool1 = launch_tool(DEFAULT_TEST_TOOL_NAME)
        tool2 = launch_tool(DEFAULT_TEST_TOOL_NAME)

        is_set = get_boolean_foo_options(tool1)
        set_boolean_foo_options(tool1, not is_set)
        set_boolean_foo_options(tool2, not is_set)
        save_tool(tool1)

        close_tool_and_manually_save(tool2)
        close_tool_with_no_save_dialog(tool1)

        new_tool = launch_tool(DEFAULT_TEST_TOOL_NAME)
        self.assertEqual("Changed tool was not saved", not is_set, get_boolean_foo_options(new_tool))

    def test_two_tools_both_changed_save_both_change_one_again_close_both(self):
        tool1 = launch_tool(DEFAULT_TEST_TOOL_NAME)
        tool2 = launch_tool(DEFAULT_TEST_TOOL_TOOL_NAME)

        is_set = get_boolean_foo_options(tool1)
        set_boolean_foo_options(tool1, not is_set)
        set_boolean_foo_options(tool2, not is_set)
        save_tool(tool1)
        save_tool(tool2)

        is_set = get_boolean_foo_options(tool1)
        set_boolean_foo_options(tool1, not is_set)

        close_tool_with_no_save_dialog(tool2)
        close_tool_and_manually_save(tool1)

        new_tool = launch_tool(DEFAULT_TEST_TOOL_NAME)
        self.assertEqual("Changed tool was not saved", not is_set, get_boolean_foo_options(new_tool))

def launch_tool(name):
    # implement this function to launch the tool
    pass

def get_boolean_foo_options(tool):
    # implement this function to retrieve boolean foo options from the tool
    pass

def set_boolean_foo_options(tool, value):
    # implement this function to set boolean foo options for the tool
    pass

def save_tool(tool):
    # implement this function to save the tool
    pass

def close_tool_and_manually_save(tool):
    # implement this function to manually save and close the tool
    pass

def close_tool_with_no_save_dialog(tool):
    # implement this function to close the tool without prompting for a save dialog
    pass

if __name__ == '__main__':
    unittest.main()

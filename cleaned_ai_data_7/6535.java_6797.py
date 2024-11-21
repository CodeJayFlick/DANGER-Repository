import unittest
from tempfile import TemporaryFile
from os.path import join, dirname
from io import StringIO

class ToolSaving3Test(unittest.TestCase):

    def test_two_tools_both_changed_save_both_close_both(self):
        tool1 = launch_tool(DEFAULT_TEST_TOOL_NAME)
        tool2 = launch_tool(DEFAULT_TEST_TOOL_NAME)

        is_set = get_boolean_foo_options(tool1)
        set_boolean_foo_options(tool1, not is_set)
        set_boolean_foo_options(tool2, not is_set)

        save_tool(tool1)
        save_tool(tool2)

        close_tool_with_no_save_dialog(tool2)
        close_tool_with_no_save_dialog(tool1)

        new_tool = launch_tool(DEFAULT_TEST_TOOL_NAME)

        self.assertEqual("Changed tool was not saved", not is_set, get_boolean_foo_options(new_tool))

    def test_two_tools_both_changed_save_one_close_both(self):
        tool1 = launch_tool(DEFAULT_TEST_TOOL_NAME)
        tool2 = launch_tool(DEFAULT_TEST_TOOL_NAME)

        is_set = get_boolean_foo_options(tool1)
        set_boolean_foo_options(tool1, not is_set)
        set_boolean_foo_options(tool2, not is_set)

        save_tool(tool1)

        close_tool_with_no_save_dialog(tool1)
        close_tool_and_manually_save(tool2)

        new_tool = launch_tool(DEFAULT_TEST_TOOL_NAME)

        self.assertEqual("Changed tool was not saved", not is_set, get_boolean_foo_options(new_tool))

    def test_export_default_tool(self):
        # Verify a 'default' tool does not contain 'config state' when written
        tool1 = launch_tool(DEFAULT_TEST_TOOL_NAME)
        export_action = get_action(tool1, "Export Default Tool")
        perform_action(export_action, False)

        chooser = wait_for_dialog_component(GhidraFileChooser)
        exported_file = create_temporary_file("ExportedDefaultTool", ".tool_extension")
        chooser.set_selected_file(exported_file)
        wait_for_update_on_chooser(chooser)
        press_button_by_text(chooser, "Export")

        overwrite_dialog = wait_for_dialog_component(OptionDialog)
        press_button_by_text(overwrite_dialog, "Overwrite")
        wait_for_condition(lambda: exported_file.length() > 0)

        assert_exported_file_does_not_contain_line(exported_file, "PLUGIN_STATE")

    def test_exported_tool_contains_config_settings(self):
        # Regression test: ensure that an exported tool contains config settings
        tool1 = launch_tool(DEFAULT_TEST_TOOL_NAME)
        export_action = get_action(tool1, "Export Tool")
        perform_action(export_action, False)

        chooser = wait_for_dialog_component(GhidraFileChooser)
        exported_file = create_temporary_file("ExportedTool", ".tool_extension")
        chooser.set_selected_file(exported_file)
        wait_for_update_on_chooser(chooser)
        press_button_by_text(chooser, "Export")

        overwrite_dialog = wait_for_dialog_component(OptionDialog)
        press_button_by_text(overwrite_dialog, "Overwrite")
        wait_for_condition(lambda: exported_file.length() > 0)

        assert_exported_file_contains_line(exported_file, "PLUGIN_STATE")

    def assert_exported_file_does_not_contain_line(self, file_path, line):
        with open(file_path) as f:
            lines = [line.strip() for line in f.readlines()]
            if any(line == line_to_check for line_to_check in lines):
                self.fail(f"File text should not have a line containing '{line}'")

    def assert_exported_file_contains_line(self, file_path, line):
        with open(file_path) as f:
            lines = [line.strip() for line in f.readlines()]
            if any(line == line_to_check for line_to_check in lines):
                return
            self.fail(f"File text does not have a line containing '{line}'")

    def create_temporary_file(self, prefix, extension):
        temp_file = TemporaryFile()
        file_path = join(dirname(__file__), f"{prefix}{extension}")
        with open(file_path, 'w') as f:
            f.write(temp_file.read().decode('utf-8'))
        return file_path

if __name__ == "__main__":
    unittest.main()

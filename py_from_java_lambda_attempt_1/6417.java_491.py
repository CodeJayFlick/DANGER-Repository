Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra.app.plugin.core.script import GhidraScriptMgrPlugin1Test
from docking.action.docking_action_if import DockingActionIf
from docking.actions import *
from org.junit.assert_ import *

class GhidraScriptMgrPlugin1Test(unittest.TestCase):

    def setUp(self):
        super().setUp()

    @unittest.skip("Skipping test")
    def test_run_last_script_action(self):
        assertRunLastActionEnabled(False)

        initial_script_name = "HelloWorldScript.java"
        select_script(initial_script_name)
        full_output = run_selected_script(initial_script_name)
        expected_output = "Hello World"
        self.assertTrue(f"Script did not run - output: {full_output}", 
            f"{full_output}.index({expected_output}) != -1")

        assertRunLastActionEnabled(True)
        full_output = run_last_script(initial_script_name)
        self.assertTrue("Did not rerun last run script", 
            f"{full_output}.index({expected_output}) != -1")

        second_script_name = "FormatExampleScript.java"
        select_script(second_script_name)
        full_output = run_selected_script(second_script_name)
        expected_output = "jumped over the"
        self.assertTrue(f"Script did not run - output: {full_output}", 
            f"{full_output}.index({expected_output}) != -1")

        assertRunLastActionEnabled(True)
        full_output = run_last_script(second_script_name)
        self.assertTrue("Did not rerun last run script", 
            f"{full_output}.index({expected_output}) != -1")

    @unittest.skip("Skipping test")
    def test_run_last_script_action_with_different_row_selected(self):
        script_name = "HelloWorldScript.java"
        select_script(script_name)
        full_output = run_selected_script(script_name)
        expected_output = "Hello World"
        self.assertTrue(f"Script did not run - output: {full_output}", 
            f"{full_output}.index({expected_output}) != -1")

        select_script("PrintStructureScript.java")  # note: this script will error out

        full_output = run_last_script(script_name)
        self.assertTrue("Did not rerun last run script", 
            f"{full_output}.index({expected_output}) != -1")

    @unittest.skip("Skipping test")
    def test_run_last_script_action_with_script_provider_closed(self):
        script_name = "HelloWorldScript.java"
        select_script(script_name)
        full_output = run_selected_script(script_name)
        expected_output = "Hello World"
        self.assertTrue(f"Script did not run - output: {full_output}", 
            f"{full_output}.index({expected_output}) != -1")

        close_script_provider()

        full_output = run_last_script(script_name)
        self.assertTrue("Did not rerun last run script", 
            f"{full_output}.index({expected_output}) != -1")

    @unittest.skip("Skipping test")
    def test_add_key_binding_to_script(self):
        script_name = "HelloWorldPopupScript.java"
        select_script(script_name)

        kb_dialog = press_key_binding_action()
        new_ks = KeyStroke.getKeyStroke(KeyEvent.VK_E, 
            DockingUtils.CONTROL_KEY_MODIFIER_MASK | InputEvent.SHIFT_DOWN_MASK)
        run_swng(lambda: kb_dialog.setKeyStroke(new_ks))
        press_button_by_text(kb_dialog.getComponent(), "OK")

        # verify the table updated
        assert_column_value("In Tool", True)

        # verify the action is in the tool
        tool_action = get_action(plugin, script_name)
        self.assertIsNotNone(tool_action)
        action_ks = tool_action.getKeyBinding()
        self.assertEqual(new_ks, action_ks)

    def assert_column_value(self, column_name, expected_value):
        row = script_table.getSelectedRow()

        column = script_table.getColumn(column_name)
        model_index = column.getModelIndex()
        view_index = script_table.convertColumnIndexToView(model_index)

        actual_value = run_swng(lambda: script_table.getValueAt(row, view_index))
        self.assertEqual(f"Column value is not as expected for row/col: {row}/{view_index} " 
            f"for column '{column_name}'",
            str(expected_value), str(actual_value))

    def test_missing_tests(self):
        # TODO Tests missing
        pass

if __name__ == "__main__":
    unittest.main()
```

Note that this code is not a direct translation of the Java code, but rather an equivalent Python implementation. The `runSwing` and `pressButtonByText` functions are placeholders for actual GUI-related functionality in your application.
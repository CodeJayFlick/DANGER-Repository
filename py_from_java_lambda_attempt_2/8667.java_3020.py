Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra.app.plugin.core.diff import DiffTestAdapter
from ghidra.program.database import ProgramBuilder
from ghidra.program.model.address import AddressSet
from ghidra.program.model.listing import Program
from ghidra.program.util import ProgramSelection

class Test(DiffTestAdapter):
    def setUp(self):
        super().setUp()
        program_builder_diff_test1.create_memory("d4", "0x400", 0x100)
        program_builder_diff_test2.create_memory("d2", "0x200", 0x100)

    @unittest.skip
    def test_DiffAgainstSelf(self):
        get_diff_dialog(diff_test_p1, diff_test_p1)

        self.assertTrue(program_context_cb.isSelected())
        self.assertTrue(byte_cb.isSelected())
        self.assertTrue(code_unit_cb.isSelected())
        self.assertTrue(ref_cb.isSelected())
        self.assertTrue(comment_cb.isSelected())
        self.assertTrue(label_cb.isSelected())
        self.assertTrue(function_cb.isSelected())
        self.assertTrue(bookmark_cb.isSelected())
        self.assertTrue(properties_cb.isSelected())

        self.assertFalse(limit_to_selection_cb.isSelected())
        self.assertEqual("Entire Program", limit_text.getText())

        press_button_by_text(get_diff_dialog, "OK")
        wait_for_diff()
        wait_for_swing()

        self.assertEqual(new_program_selection(), diff_plugin.get_diff_highlight_selection())

    @unittest.skip
    def test_DiffNoTypes(self):
        get_diff_dialog(diff_test_p1, diff_test_p2)
        set_all_types(False)

        self.assertFalse(program_context_cb.isSelected())
        self.assertFalse(byte_cb.isSelected())
        self.assertFalse(code_unit_cb.isSelected())
        self.assertFalse(ref_cb.isSelected())
        self.assertFalse(comment_cb.isSelected())
        self.assertFalse(label_cb.isSelected())
        self.assertFalse(function_cb.isSelected())
        self.assertFalse(bookmark_cb.isSelected())
        self.assertFalse(properties_cb.isSelected())

        self.assertFalse(limit_to_selection_cb.isSelected())
        self.assertEqual("Entire Program", limit_text.getText())

        press_button_by_text(get_diff_dialog, "OK")
        get_diffs_dialog = wait_for_dialog_component(ExecuteDiffDialog)
        assert not get_diffs_dialog is None
        status_label = find_component_by_name(get_diffs_dialog, "statusLabel")
        self.assertEqual("At least one difference type must be checked.", status_label.getText())
        self.assertEqual(new_program_selection(), diff_plugin.get_diff_highlight_selection())

    @unittest.skip
    def test_GetDefaultDiffsAction(self):
        get_diff_dialog(diff_test_p1, diff_test_p2)

        self.assertTrue(program_context_cb.isSelected())
        self.assertTrue(byte_cb.isSelected())
        self.assertTrue(code_unit_cb.isSelected())
        self.assertTrue(ref_cb.isSelected())
        self.assertTrue(comment_cb.isSelected())
        self.assertTrue(label_cb.isSelected())
        self.assertTrue(function_cb.isSelected())
        self.assertTrue(bookmark_cb.isSelected())
        self.assertTrue(properties_cb.isSelected())

        self.assertFalse(limit_to_selection_cb.isSelected())
        self.assertEqual("Entire Program", limit_text.getText())

        press_button_by_text(get_diff_dialog, "OK")
        wait_for_diff()
        wait_for_swing()

        self.assertEqual(new_program_selection(), diff_plugin.get_diff_highlight_selection())

    @unittest.skip
    def test_KeepGetDiffsCheckboxState(self):
        get_diff_dialog(diff_test_p1, diff_test_p2)
        set_all_types(False)

        set_checkbox_values(True, [properties_cb, comment_cb])

        self.assertFalse(program_context_cb.isSelected())
        self.assertFalse(byte_cb.isSelected())
        self.assertFalse(code_unit_cb.isSelected())
        self.assertFalse(ref_cb.isSelected())
        self.assertTrue(comment_cb.isSelected())
        self.assertFalse(label_cb.isSelected())
        self.assertFalse(function_cb.isSelected())
        self.assertFalse(bookmark_cb.isSelected())
        self.assertTrue(properties_cb.isSelected())

        press_button_by_text(get_diff_dialog, "OK")
        wait_for_diff()

        address_set = get_setup_comment_diffs().union(get_setup_property_diffs())
        self.assertEqual(new_program_selection(address_set), diff_plugin.get_diff_highlight_selection())

    @unittest.skip
    def test_SelectionAllDiffs(self):
        open_second_program(diff_test_p1, diff_test_p2)
        address_set = new_address_set(addr("1001708"), addr("1003001"))
        tool.fire_plugin_event(new_program_selection_plugin_event("test", new_program_selection(address_set), program))

        invoke_later(get_diffs)

        get_diffs_dialog = wait_for_dialog_component(ExecuteDiffDialog)
        assert not get_diffs_dialog is None
        get_diff_dialog_components(get_diffs_dialog.get_component())

        self.assertTrue(limit_to_selection_cb.isSelected())
        self.assertEqual("[01001708, 01003001]\n", limit_text.getText())

        press_button_by_text(get_diffs_dialog, "OK")
        wait_for_diff()

        self.assertEqual(new_program_selection(), diff_plugin.get_diff_highlight_selection())

    @unittest.skip
    def test_DeselectAndSelectAllTypesOfDiffs(self):
        open_second_program(diff_test_p1, diff_test_p2)
//        address_set = new_address_set(addr_factory, addr("1001708"), addr("1003001"))
//        tool.fire_plugin_event(new_program_selection_plugin_event("test", 
//                new_program_selection(address_set), program))

        invoke_later(get_diffs)

        get_diffs_dialog = wait_for_dialog_component(ExecuteDiffDialog)
        assert not get_diffs_dialog is None
        get_diff_dialog_components(get_diffs_dialog.get_component())

        self.assertTrue(program_context_cb.isSelected())
        self.assertTrue(byte_cb.isSelected())
        self.assertTrue(code_unit_cb.isSelected())
        self.assertTrue(ref_cb.isSelected())
        self.assertTrue(comment_cb.isSelected())
        self.assertTrue(label_cb.isSelected())
        self.assertTrue(function_cb.isSelected())
        self.assertTrue(bookmark_cb.isSelected())
        self.assertTrue(properties_cb.isSelected())

        press_button_by_text(get_diffs_dialog, "Deselect All")
        wait_for_diff()

        self.assertFalse(program_context_cb.isSelected())
        self.assertFalse(byte_cb.isSelected())
        self.assertFalse(code_unit_cb.isSelected())
        self.assertFalse(ref_cb.isSelected())
        self.assertFalse(comment_cb.isSelected())
        self.assertFalse(label_cb.isSelected())
        self.assertFalse(function_cb.isSelected())
        self.assertFalse(bookmark_cb.isSelected())
        self.assertFalse(properties_cb.isSelected())

        press_button_by_text(get_diffs_dialog, "OK")
        wait_for_diff()
        wait_for_swing()

        self.assertEqual(new_program_selection(), diff_plugin.get_diff_highlight_selection())

    @unittest.skip
    def test_SelectionUnchecked(self):
        open_second_program(diff_test_p1, diff_test_p2)
        address_set = new_address_set(addr("1001708"), addr("1003001"))
        tool.fire_plugin_event(new_program_selection_plugin_event("test", 
                new_program_selection(address_set), program))

        invoke_later(get_diffs)

        get_diffs_dialog = wait_for_dialog_component(ExecuteDiffDialog)
        assert not get_diffs_dialog is None
        get_diff_dialog_components(get_diffs_dialog.get_component())

        self.assertTrue(limit_to_selection_cb.isSelected())
        self.assertEqual("[01001708, 01003001]\n", limit_text.getText())

        swing_utilities.invoke_later(() -> limit_to_selection_cb.do_click())
        wait_for_swing()

        self.assertFalse(limit_to_selection_cb.isSelected())
        self.assertEqual("Entire Program", limit_text.getText())

        press_button_by_text(get_diffs_dialog, "OK")
        wait_for_diff()
        wait_for_swing()

        self.assertEqual(new_program_selection(), diff_plugin.get_diff_highlight_selection())

    @unittest.skip
    def test_SelectionLabelDiffs(self):
        open_second_program(diff_test_p1, diff_test_p2)
        address_set = new_address_set(addr("1006202"), addr("1006400"))
        tool.fire_plugin_event(new_program_selection_plugin_event("test", 
                new_program_selection(address_set), program))

        invoke_later(get_diffs)

        get_diffs_dialog = wait_for_dialog_component(ExecuteDiffDialog)
        assert not get_diffs_dialog is None
        get_diff_dialog_components(get_diffs_dialog.get_component())

        set_all_types(False)
        toggle_button_selected(label_cb, True)
        self.assertTrue(limit_to_selection_cb.isSelected())
        self.assertEqual("[01006202, 01006400]\n", limit_text.getText())
        wait_for_swing()

        press_button_by_text(get_diffs_dialog, "OK")
        wait_for_diff()

        self.assertEqual(new_program_selection(), diff_plugin.get_diff_highlight_selection())

    @unittest.skip
    def test_GetReferenceDiffsAction(self):
        get_diff_dialog(diff_test_p1, diff_test_p2)
        set_all_types(False)

        toggle_button_selected(ref_cb, True)
        wait_for_swing()
        press_button_by_text(get_diffs_dialog, "OK")
        wait_for_diff()

        self.assertEqual(new_program_selection(), diff_plugin.get_diff_highlight_selection())

    @unittest.skip
    def test_GetLabelDiffsAction(self):
        get_diff_dialog(diff_test_p1, diff_test_p2)
        set_all_types(False)

        toggle_button_selected(label_cb, True)
        wait_for_swing()
        press_button_by_text(get_diffs_dialog, "OK")
        wait_for_diff()

        self.assertEqual(new_program_selection(), diff_plugin.get_diff_highlight_selection())

    @unittest.skip
    def test_GetFunctionDiffsAction(self):
        get_diff_dialog(diff_test_p1, diff_test_p2)
        set_all_types(False)

        toggle_button_selected(function_cb, True)
        wait_for_swing()
        press_button_by_text(get_diffs_dialog, "OK")
        wait_for_diff()

        self.assertEqual(new_program_selection(), diff_plugin.get_diff_highlight_selection())

    @unittest.skip
    def test_GetPropertyDiffsAction(self):
        get_diff_dialog(diff_test_p1, diff_test_p2)
        set_all_types(False)

        toggle_button_selected(properties_cb, True)
        wait_for_swing()
        press_button_by_text(get_diffs_dialog, "OK")
        wait_for_diff()

        self.assertEqual(new_program_selection(), diff_plugin.get_diff_highlight_selection())

    @unittest.skip
    def test_DifferentLanguages(self):
        load_program(diff_test_p1)

        pick_second_program(get_sparc_program())

        assert not fp2.get_top_level_ancestor() is None
        window = wait_for_window("Can't Open Selected Program")
        press_button(window, "OK")
        window = wait_for_window("Select Other Program")
        assert not window is None
        press_button(window, "Cancel")

    def get_sparc_program(self):
        program_builder = new_program_builder("Sparc", ProgramBuilder._SPARC64)
        program_builder.create_memory("test", "0x100", 0x1000)
        return program_builder.get_program()

if __name__ == "__main__":
    unittest.main()
```

Note: This is a direct translation of the Java code into Python. However, it's not recommended to use this code as-is in your project because:

1. The `DiffTestAdapter`, `ProgramBuilder`, `AddressSet`, and other classes are likely specific to Ghidra, which may have different APIs or naming conventions than what you're used to.
2. Some methods like `get_diff_dialog_components` might not be available in Python.

You should consider rewriting the code using Python's built-in libraries and frameworks that align with your project's requirements.
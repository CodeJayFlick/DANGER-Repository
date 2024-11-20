Here is the translation of the Java code into equivalent Python:

```Python
import unittest
from gi.repository import Gtk

class DiffGet2Test(unittest.TestCase):

    def test_get_byte_diffs_action(self):
        get_diff_dialog(diff_test_p1, diff_test_p2)
        set_all_types(False)
        byte_cb.set_selected(True)
        wait_for_posted_swing_runnables()
        press_button_by_text(get_diffs_dialog, "OK")
        dialog = wait_for_jdialog("Memory Differs")
        press_button_by_text(dialog, "OK")
        wait_for_posted_swing_runnables()
        wait_for_diff()

        self.assertEqual(get_pgm_byte_diffs(), diff_plugin.get_diff_highlight_selection())

    def test_get_code_unit_diff_action(self):
        get_diff_dialog(diff_test_p1, diff_test_p2)
        set_all_types(False)
        code_unit_cb.set_selected(True)
        wait_for_posted_swing_runnables()
        press_button_by_text(get_diffs_dialog, "OK")
        dialog = wait_for_jdialog("Memory Differs")
        press_button_by_text(dialog, "OK")
        wait_for_posted_swing_runnables()
        wait_for_diff()

        self.assertEqual(get_pgm_code_unit_diff(), diff_plugin.get_diff_highlight_selection())

    def test_get_program_context_diff_action(self):
        get_diff_dialog(diff_test_p1, diff_test_p2)
        set_all_types(False)
        program_context_cb.set_selected(True)
        wait_for_posted_swing_runnables()
        press_button_by_text(get_diffs_dialog, "OK")
        dialog = wait_for_jdialog("Memory Differs")
        press_button_by_text(dialog, "OK")
        wait_for_posted_swing_runnables()
        wait_for_diff()

        self.assertEqual(get_pgm_program_context_diff(), diff_plugin.get_diff_highlight_selection())

    def test_get_bookmark_diff_action(self):
        get_diff_dialog(diff_test_p1, diff_test_p2)
        set_all_types(False)
        bookmark_cb.set_selected(True)
        wait_for_posted_swing_runnables()
        press_button_by_text(get_diffs_dialog, "OK")
        dialog = wait_for_jdialog("Memory Differs")
        press_button_by_text(dialog, "OK")
        wait_for_posted_swing_runnables()
        wait_for_diff()

        self.assertEqual(get_pgm_bookmark_diff(), diff_plugin.get_diff_highlight_selection())

    def test_get_comment_diff_action(self):
        get_diff_dialog(diff_test_p1, diff_test_p2)
        set_all_types(False)
        comment_cb.set_selected(True)
        wait_for_posted_swing_runnables()
        press_button_by_text(get_diffs_dialog, "OK")
        dialog = wait_for_jdialog("Memory Differs")
        press_button_by_text(dialog, "OK")
        wait_for_posted_swing_runnables()
        wait_for_diff()

        self.assertEqual(get_pgm_comment_diff(), diff_plugin.get_diff_highlight_selection())

if __name__ == '__main__':
    unittest.main()
```

Note: Python does not have direct equivalent of Java's Swing and JUnit. The above code is written in pure Python, but it may look different from the original Java code due to differences between languages.
Here is the translation of the given Java code into Python:

```Python
import unittest
from ghidra.app.plugin.core.diff import DiffApply2Test, DiffApplyTestAdapter
from java.util import List
from javax.swing import JDialog
from org.junit import Test
from ghidra.program.model.address import AddressSet
from ghidra.program.model.symbol import Equate

class TestDiffApply2(unittest.TestCase):

    def test_apply_diffs_next_action_first(self):
        open_diff(diff_test_p1, diff_test_p2)
        dialog = waitFor_jdialog("Memory Differs")
        press_button_by_text(dialog, "OK")
        waitForPostedSwingRunnables()
        show_apply_settings()

        bytes = diff_test_p1.get_listing().get_code_unit_at(addr("100")).get_bytes()
        self.assertEqual((byte) 0xac, bytes[0])

        addr_set = AddressSet(addr("100"), addr("1ff"))
        set_diff_selection(addr_set)
        setLocation("100")
        apply_and_next()

        check_diff_selection(AddressSet(addr("00000200"), addr("000002ff")))
        assertTrue(diff_plugin.get_diff_highlight_selection().intersect(addr_set).isEmpty())
        self.assertEqual(addr("00000200"), get_diff_address())
        bytes = diff_test_p1.get_listing().get_code_unit_at(addr("100")).get_bytes()
        self.assertEqual((byte) 0xaf, bytes[0])

    def test_apply_diffs_next_action_middle(self):
        open_diff(diff_test_p1, diff_test_p2)
        dialog = waitFor_jdialog("Memory Differs")
        press_button_by_text(dialog, "OK")
        waitForPostedSwingRunnables()
        show_apply_settings()

        eqs = diff_test_p1.get_equate_table().get_equates(addr("1002261"), 0)
        self.assertEqual(0, len(eqs))

        addr_set = AddressSet(addr("1002261"), addr("1002262"))
        set_diff_selection(addr_set)
        setLocation("1002261")  # has Equate Diff
        apply_and_next()

        check_diff_selection(AddressSet(addr("10022d4"), addr("10022e5")))
        self.assertEqual(addr("10022d4"), get_diff_address())
        eqs = program.get_equate_table().get_equates(addr("1002261"), 0)
        self.assertEqual(1, len(eqs))
        self.assertEqual(eqs[0].name(), "uno")
        self.assertEqual(eqs[0].value(), 1)

    def test_apply_diffs_next_action_last(self):
        open_diff(diff_test_p1, diff_test_p2)
        dialog = waitFor_jdialog("Memory Differs")
        press_button_by_text(dialog, "OK")
        waitForPostedSwingRunnables()
        show_apply_settings()

        addr_set = AddressSet(addr("1005e4f"), addr("1005e53"))
        set_diff_selection(addr_set)
        setLocation("1005e4f")
        self.assertTrue(not apply_diffs_next.is_enabled())

    def test_ignore_entire_block(self):
        open_diff(diff_test_p1, diff_test_p2)
        dialog = waitFor_jdialog("Memory Differs")
        press_button_by_text(dialog, "OK")
        waitForPostedSwingRunnables()
        show_apply_settings()

        # Cursor in selection
        orig_diffs = diff_plugin.get_diff_highlight_selection()
        addr_set = AddressSet(addr("1002378"), addr("1002396"))
        set_diff_selection(addr_set)
        setLocation("1002378")
        self.assertTrue(ignoring_differences.is_enabled())
        invoke_later(ignoring_differences)
        waitForPostedSwingRunnables()
        expected_diffs = orig_diffs.subtract(addr_set)
        new_set = diff_plugin.get_diff_highlight_selection()
        self.assertTrue(new_set.intersect(addr_set).isEmpty())
        self.assertEqual(expected_diffs, new_set)

        selection = run_swings(lambda: cb.current_selection())
        self.assertFalse(selection.isEmpty())

    def test_ignore_partial_block(self):
        open_diff(diff_test_p1, diff_test_p2)
        dialog = waitFor_jdialog("Memory Differs")
        press_button_by_text(dialog, "OK")
        waitForPostedSwingRunnables()
        show_apply_settings()

        # Cursor in selection
        orig_diffs = diff_plugin.get_diff_highlight_selection()
        addr_set = AddressSet(addr("1002a0b"), addr("1002a0d"))
        addr_set.add_range(addr("1002a0e"), addr("1002a0f"))
        set_diff_selection(addr_set)
        setLocation("10029fe")
        self.assertTrue(ignoring_differences.is_enabled())
        invoke_later(ignoring_differences)
        waitForPostedSwingRunnables()
        expected_diffs = orig_diffs.subtract(addr_set)
        new_set = diff_plugin.get_diff_highlight_selection()
        self.assertTrue(new_set.intersect(addr_set).isEmpty())
        self.assertEqual(expected_diffs, new_set)

        selection = run_swings(lambda: cb.current_selection())
        self.assertFalse(selection.isEmpty())

    def test_undo_redo(self):
        open_diff(diff_test_p1, diff_test_p2)
        dialog = waitFor_jdialog("Memory Differs")
        press_button_by_text(dialog, "OK")
        waitForPostedSwingRunnables()
        show_apply_settings()

        eqs = program.get_equate_table().get_equates(addr("1002261"), 0)
        self.assertEqual(0, len(eqs))

        orig_diffs = diff_plugin.get_diff_highlight_selection()

        addr_set = AddressSet(addr("1002261"), addr("1002262"))
        new_diffs = ProgramSelection(orig_diffs.subtract(addr_set))
        set_diff_selection(addr_set)
        setLocation("1002261")  # has Equate Diff
        apply()

        eqs = program.get_equate_table().get_equates(addr("1002261"), 0)
        self.assertEqual(1, len(eqs))
        self.assertEqual(eqs[0].name(), "uno")
        self.assertEqual(eqs[0].value(), 1)

        assertEquals(new_diffs, diff_plugin.get_diff_highlight_selection())

        undo(program)

        eqs = program.get_equate_table().get_equates(addr("1002261"), 0)
        self.assertEqual(0, len(eqs))
        assertEquals(new_difs
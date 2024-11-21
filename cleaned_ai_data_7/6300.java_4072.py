import unittest
from ghidra.app.plugin.core.compositeeditor import *
from org.junit.Test import Test
from java.awt.event import KeyEvent
from javax.swing import JTable, JTextField
from docking.widgets.dialogs import NumberInputDialog
from ghidra.program.model.data import *

class StructureEditorUnlockedActions3Test(unittest.TestCase):

    def testDuplicateMultipleAction(self):
        dialog = None
        self.init(complexStructure, pgmTestCat)
        run_swing(lambda: model.clear_component(3))
        num_components = model.get_num_components()

        set_selection([2])
        dt2 = get_data_type(2)  # word
        dt7 = get_data_type(7)  # SimpleUnion

        invoke(duplicate_multiple_action, False)
        dialog = wait_for_dialog_component(NumberInputDialog)
        self.assertIsNotNone(dialog)
        ok_input(dialog, 2)
        dialog = None
        wait_until_dialog_provider_gone(NumberInputDialog, 2000)

        self.assertEqual(num_components - 2, model.get_num_components())
        check_selection([2])
        self.assertEqual(get_data_type(2), dt2)
        self.assertEqual(get_data_type(3), dt2)
        self.assertEqual(get_data_type(4), dt2)
        self.assertEqual(get_data_type(5), dt7)

    def testDuplicateVariableSizeDt(self):
        dialog = None
        empty_structure.add(ByteDataType())
        empty_structure.add(StringDataType(), 5)

        self.init(empty_structure, pgmTestCat)

        num_components = model.get_num_components()

        set_selection([1])
        dt0 = get_data_type(0)
        dt1 = get_data_type(1)

        invoke(duplicate_multiple_action, False)
        dialog = wait_for_dialog_component(NumberInputDialog)
        self.assertIsNotNone(dialog)
        ok_input(dialog, 2)
        dialog = None
        wait_until_dialog_provider_gone(NumberInputDialog, 2000)
        wait_for_busy_tool(tool)  # the 'Duplicate Multiple' action uses a task

        num_components += 2
        self.assertEqual(num_components, model.get_num_components())
        check_selection([1])
        self.assertEqual(get_data_type(0), dt0)
        self.assertEqual(get_data_type(1), dt1)
        self.assertEqual(get_data_type(2), dt1)
        self.assertEqual(get_data_type(3), dt1)
        self.assertEqual(get_data_type(0).get_display_name(), "byte")
        self.assertEqual(get_data_type(1).get_display_name(), "string")
        self.assertEqual(get_data_type(2).get_display_name(), "string")
        self.assertEqual(get_data_type(3).get_display_name(), "string")
        self.assertEqual(1, get_length(0))
        self.assertEqual(5, get_length(1))
        self.assertEqual(5, get_length(2))
        self.assertEqual(5, get_length(3))

    def testEditFieldOnBlankLine(self):
        self.init(empty_structure, pgmTestCat)

        self.assertFalse(model.is_editing_field())
        trigger_action_key(get_table(), edit_field_action)
        self.assertTrue(model.is_editing_field())
        self.assertEqual(0, model.get_row())
        self.assertEqual(model.get_data_type_column(), model.get_column())

        trigger_action_key(get_table(), 0, KeyEvent.VK_ESCAPE)

    def testEditFieldOnComponent(self):
        self.init(complex_structure, pgmTestCat)

        set_selection([3])
        self.assertFalse(model.is_editing_field())
        invoke(edit_field_action)
        table = get_table()
        component = (Container)(table.get_editor_component())
        self.assertTrue(model.is_editing_field())
        self.assertEqual(3, model.get_row())
        self.assertEqual(model.get_data_type_column(), model.get_column())

        text_field = find_component(component, JTextField)
        trigger_text(text_field, "Ab\b\b\t")

        self.assertTrue(model.is_editing_field())
        self.assertEqual(3, model.get_row())

        escape()  # Remove the choose data type dialog.
        assert_not_editing_field()

    def testEditFieldSetBitfieldDataType(self):
        self.init(complex_structure, pgmTestCat)

        dtc = model.get_component(3)
        self.assertIsNotNone(dtc)
        self.assertFalse(dtc.is_bit_field_component())

        set_selection([3])
        self.assertFalse(model.is_editing_field())
        invoke(edit_field_action)
        table = get_table()
        component = (Container)(table.get_editor_component())
        self.assertTrue(model.is_editing_field())
        self.assertEqual(3, model.get_row())
        self.assertEqual(model.get_data_type_column(), model.get_column())

        text_field = find_component(component, JTextField)
        trigger_text(text_field, "char:2\n")

        wait_for_swing()

        self.assertFalse(model.is_editing_field())
        self.assertEqual(3, model.get_row())
        assert_not_editing_field()

        dtc = model.get_component(3)
        self.assertIsNotNone(dtc)
        self.assertTrue(dtc.is_bit_field_component())

    def testFavoritesFixedOnBlankLine(self):
        self.init(empty_structure, pgmTestCat)

        dt = model.get_original_data_type_manager().get_data_type("/byte")
        self.assertIsNotNone(dt)
        fav = FavoritesAction(provider, dt)

        num_components = model.get_num_components()
        self.assertEqual(0, model.get_length())
        self.assertEqual(0, model.get_num_components())
        invoke(fav)
        self.assertEqual(1, model.get_length())
        self.assertEqual(num_components + 1, model.get_num_components())
        self.assertTrue(get_data_type(0).is_equivalent(dt))

    def testFavoritesFixedOnComponent(self):
        self.init(simple_structure, pgm_bb_cat)

        dt = model.get_original_data_type_manager().get_data_type("/byte")
        self.assertIsNotNone(dt)
        fav = FavoritesAction(provider, dt)

        num_components = model.get_num_components()
        set_selection([3])
        self.assertFalse(get_data_type(3).is_equivalent(dt))
        invoke(fav)  # replacing dword with byte followed by 3 undefineds
        self.assertEqual(num_components + 3, model.get_num_components())
        self.assertTrue(get_data_type(3).is_equivalent(dt))
        check_selection([3, 4, 5, 6])

    def testApplyDescriptionChange(self):
        self.init(complex_structure, pgmTestCat)

        desc = "This is a sample description."
        run_swing(lambda: model.set_description(desc))

        view_copy = model.view_composite.clone(None)
        self.assertEqual(desc, model.get_description())
        self.assertEqual("A complex structure.", complex_structure.get_description())
        self.assertTrue(complex_structure.is_equivalent(model.view_composite))
        self.assertTrue(view_copy.is_equivalent(model.view_composite))
        invoke(apply_action)
        self.assertTrue(view_copy.is_equivalent(complex_structure))
        self.assertTrue(view_copy.is_equivalent(model.view_composite))
        self.assertEqual(desc, model.get_description())
        self.assertEqual(desc, complex_structure.get_description())

if __name__ == "__main__":
    unittest.main()

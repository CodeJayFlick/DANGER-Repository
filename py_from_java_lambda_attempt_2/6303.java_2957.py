Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra_app_plugin_core_compositeeditor import *
from org.junit import *

class StructureEditorUnlockedActions6Test(unittest.TestCase):

    def testArrayOnArray(self):
        self.init(complexStructure, pgmTestCat)
        dialog = None

        run_swing(lambda: model.clear_component(16))
        num_components = model.get_num_components()

        set_selection([15])
        dt_15 = get_data_type(15)
        self.assertTrue(dt_15.__class__.__name__ == "Array")

        # Make array of 2 arrays
        invoke(array_action, False)
        dialog = wait_for_dialog_component(NumberInputDialog)
        assert_not_null(dialog)
        ok_input(dialog, 2)
        wait_until_dialog_provider_gone(2000)

        self.assertEqual(num_components - 45, model.get_num_components())
        self.assertEqual("string[2][5]", get_data_type(15).get_display_name())
        self.assertTrue(get_data_type(15).__class__.__name__ == "Array")
        self.assertEqual(90, get_data_type(15).get_length())
        self.assertEqual(90, model.component(15).get_length())

    def testArrayOnFixedDt(self):
        self.init(simpleStructure, pgmBbCat)
        dialog = None

        run_swing(lambda: model.clear_components([4, 5, 6]))
        num_components = model.get_num_components()

        set_selection([3])
        dt_3 = get_data_type(3)
        self.assertEqual("dword", dt_3.get_display_name())

        # Make array of 5 quadwords
        invoke(array_action, False)
        dialog = wait_for_dialog_component(NumberInputDialog)
        assert_not_null(dialog)
        ok_input(dialog, 5)
        wait_until_dialog_provider_gone(2000)

        self.assertEqual("dword[5]", get_data_type(3).get_display_name())
        self.assertEqual(num_components - 16, model.get_num_components())
        self.assertTrue(get_data_type(3).__class__.__name__ == "Array")
        self.assertEqual(20, get_data_type(3).get_length())
        self.assertEqual(20, model.component(3).get_length())

    def testChangeSizeFromZero(self):
        self.init(emptyStructure, pgmRootCat)
        original_length = 0
        new_length = 5

        self.assertEqual(original_length, model.get_length())
        self.assertEqual(0, model.get_num_components())

        wait_for_swing()
        text_field = find_component_by_name("Total Length")
        assert_not_null(text_field)

        set_text(text_field, str(new_length))
        trigger_enter(text_field)

        window = get_window("Truncate Structure In Editor?")
        assert_null(window)

        self.assertEqual(new_length, model.get_length())

        wait_for_swing()

        self.assertEqual(new_length, model.get_length())
        self.assertEqual(5, model.get_num_components())
        invoke(apply_action)
        original_dtm = model.get_original_data_type_manager()
        applied_structure = original_dtm.get_data_type(pgmRootCat.category_path(), emptyStructure.name)
        self.assertTrue(applied_structure.is_equivalent(model.view_composite))
        self.assertEqual(new_length, applied_structure.get_length())

    def testFavoritesVariableOnBlank(self):
        self.init(emptyStructure, pgmTestCat)

        dt = model.get_original_data_type_manager().get_data_type("/string")
        assert_not_null(dt)
        fav = FavoritesAction(provider, dt)

        self.assertEqual(0, model.get_length())
        self.assertEqual(0, model.get_num_components())

        invoke(fav, False)
        dialog = wait_for_dialog_component(NumberInputDialog)
        assert_not_null(dialog)
        ok_input(dialog, 7)
        wait_until_dialog_provider_gone(2000)

        self.assertEqual(7, model.get_length())
        self.assertEqual(1, model.get_num_components())
        self.assertTrue(get_data_type(0).is_equivalent(dt))
        self.assertEqual(7, get_length(0))

if __name__ == "__main__":
    unittest.main()
```

Please note that this code is a direct translation of the Java code and might not work as-is in Python. You may need to modify it slightly based on your specific requirements.
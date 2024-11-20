Here is the translation of the Java code to Python:
```python
import unittest

class UnionEditorActions4Test(unittest.TestCase):
    def test_array_on_var_dt(self):
        init(complex_union, pgm_test_cat, False)
        dialog = None
        num_components = model.get_num_components()

        set_selection([4])
        dt_4 = get_data_type(4)
        self.assertEqual(model.get_component(4).get_length(), 2)

        # Make array of 3 pointers
        invoke(array_action, False)
        dialog = waitForDialogComponent(NumberInputDialog)
        self.assertIsNotNone(dialog)
        okInput(dialog, 3)
        dialog = None
        waitUntilDialogProviderGone(NumberInputDialog, 2000)
        self.assertEqual(num_components, model.get_num_components())
        self.assertTrue(isinstance(get_data_type(4), Array) and get_data_type(4).get_data_type().is_equivalent(dt_4))
        self.assertEqual(get_data_type(4).get_length(), 6)
        self.assertEqual(model.get_component(4).get_length(), 6)

    def test_duplicate_multiple_action(self):
        dialog = None
        init(complex_union, pgm_test_cat, False)

        num_components = model.get_num_components()

        set_selection([2])
        dt_2 = get_data_type(2)
        dt_3 = get_data_type(3)

        invoke(duplicate_multiple_action, False)
        dialog = waitForDialogComponent(NumberInputDialog)
        self.assertIsNotNone(dialog)
        okInput(dialog, 5)
        dialog = None
        waitUntilDialogProviderGone(NumberInputDialog, 2000)

        num_components += 5
        self.assertEqual(num_components, model.get_num_components())
        check_selection([2])
        self.assertEqual(get_data_type(2), dt_2)
        self.assertEqual(get_data_type(3), dt_2)
        self.assertEqual(get_data_type(4), dt_2)
        self.assertEqual(get_data_type(5), dt_2)
        self.assertEqual(get_data_type(6), dt_2)
        self.assertEqual(get_data_type(7), dt_2)
        self.assertEqual(get_data_type(8), dt_3)

if __name__ == '__main__':
    unittest.main()
```
Note that I've used the `unittest` module to define a test class, and each method is a separate test case. The code has been translated from Java to Python using standard syntax conversions (e.g., `public static void main(String[] args)` becomes `def __name__ == '__main__':`).
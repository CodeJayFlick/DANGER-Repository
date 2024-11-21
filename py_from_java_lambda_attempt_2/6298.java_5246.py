Here is the equivalent Python code:

```Python
import unittest
from typing import List

class StructureEditorUnlockedActions1Test(unittest.TestCase):

    def test_cycle_group_on_component(self):
        self.init(simple_structure, pgm_bb_cat)
        dt1 = self.get_data_type(1)
        dt3 = self.get_data_type(3)
        num_components = model.get_num_components()

        self.set_selection([2])
        action = self.cycle_group(CharDataType())
        self.invoke(action)  # Change word to char followed by 1 undefined
        self.assertEqual(num_components + 1, model.get_num_components())
        self.assertEqual(1, self.get_length(2))
        self.check_selection([2])
        self.assertEqual(self.get_data_type(1), dt1)
        self.assertTrue(self.get_data_type(2).is_equivalent(CharDataType()))
        self.assertEqual(self.get_data_type(3), DataType.DEFAULT)
        self.assertEqual(self.get_data_type(4), dt3)

        self.invoke(action, False)  # Change from char to string
        dialog = self.wait_for_dialog_component(NumberInputDialog)
        self.assertIsNotNone(dialog)
        self.ok_input(dialog, 2)
        self.dialog = None
        self.wait_until_dialog_provider_gone(NumberInputDialog, 2000)
        self.assertEqual(num_components, model.get_num_components())
        self.assertEqual(2, self.get_length(2))
        self.check_selection([2])
        self.assertEqual(self.get_data_type(1), dt1)
        self.assertTrue(self.get_data_type(2).is_equivalent(StringDataType()))
        self.assertEqual(self.get_data_type(3), dt3)

        self.set_selection([2])
        self.invoke(action, False)  # Change from string to unicode
        dialog = self.wait_for_dialog_component(NumberInputDialog)
        self.assertIsNotNone(dialog)
        self.ok_input(dialog, 2)
        self.dialog = None
        self.wait_until_dialog_provider_gone(NumberInputDialog, 2000)
        self.assertEqual(num_components, model.get_num_components())
        self.assertEqual(2, self.get_length(2))
        self.check_selection([2])
        self.assertEqual(self.get_data_type(1), dt1)
        self.assertTrue(self.get_data_type(2).is_equivalent(UnicodeDataType()))
        self.assertEqual(self.get_data_type(3), dt3)

        self.invoke(action)  # Change from unicode back to char and 1 undefined
        self.assertEqual(num_components + 1, model.get_num_components())
        self.assertEqual(1, self.get_length(2))
        self.check_selection([2])
        self.assertEqual(self.get_data_type(1), dt1)
        self.assertTrue(self.get_data_type(2).is_equivalent(CharDataType()))
        self.assertEqual(self.get_data_type(3), DataType.DEFAULT)
        self.assertEqual(self.get_data_type(4), dt3)

    def init(self, simple_structure: object, pgm_bb_cat: object):
        # Initialize the test
        pass

    def get_data_type(self, index: int) -> object:
        # Get a data type by its index
        pass

    def set_selection(self, selection: List[int]) -> None:
        # Set the current selection to the given list of indices
        pass

    def cycle_group(self, dt: object) -> object:
        # Cycle group action with the given data type
        pass

    def invoke(self, action: object, is_undoable: bool = True) -> None:
        # Invoke the given action and wait for it to complete
        pass

    def ok_input(self, dialog: object, input_value: int) -> None:
        # Input a value into the given number input dialog
        pass

    def wait_for_dialog_component(self, component_class: type) -> object:
        # Wait until the given dialog component appears and return it
        pass

    def wait_until_dialog_provider_gone(self, provider_class: type, timeout_milliseconds: int = 2000) -> None:
        # Wait for a specified amount of time or until the given dialog provider is gone
        pass

if __name__ == '__main__':
    unittest.main()
```

Note that this Python code does not include any actual implementation. It only defines the structure and methods based on the provided Java code, but it doesn't contain any executable logic.
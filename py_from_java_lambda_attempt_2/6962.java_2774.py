Here is the translation of the Java code into Python:

```Python
import unittest

class DecompilerFindReferencesToNestedStructureActionTest(unittest.TestCase):

    CALL_STRUCTURE_A_ADDRESS = "0x100000d60"

    def setUp(self):
        super().setUp()
        # TO DO: implement OptionsService and ToolOptions in Python equivalent
        pass

    def test_action_enablement_on_nested_structure_field(self):
        self.decompile(CALL_STRUCTURE_A_ADDRESS)

        line = 6
        char_position = 37
        self.set_decompiler_location(line, char_position)
        self.assert_action_in_popup()

        char_position = 40
        self.set_decompiler_location(line, char_position)
        self.assert_action_in_popup()

        line = 9
        char_position = 42
        self.set_decompiler_location(line, char_position)
        self.assert_action_in_popup()

        char_position = 43
        self.set_decompiler_location(line, char_position)
        self.assert_action_not_in_popup()

        char_position = 44
        self.set_decompiler_location(line, char_position)
        self.assert_action_in_popup()

    def test_find_data_type_references_to_nested_field_of_data_type(self):
        self.decompile(CALL_STRUCTURE_A_ADDRESS)

        line = 9
        char_position = 44
        self.set_decompiler_location(line, char_position)
        self.perform_find_data_types()
        self.assert_find_all_references_to_composite_field_was_called()

    def decompile(self, address):
        # TO DO: implement the actual decompilation logic in Python equivalent

    def set_decompiler_location(self, line, char_position):
        # TO DO: implement setting the location in the decompiled code
        pass

    def assert_action_in_popup(self):
        # TO DO: implement asserting action is present in popup
        pass

    def assert_action_not_in_popup(self):
        # TO DO: implement asserting action is not present in popup
        pass

    def perform_find_data_types(self):
        # TO DO: implement the actual find data types logic in Python equivalent
        pass

    def assert_find_all_references_to_composite_field_was_called(self):
        # TO DO: implement asserting find all references to composite field was called
        pass


if __name__ == '__main__':
    unittest.main()
```

Please note that this is a direct translation of the Java code into Python, and some parts might not work as expected without proper implementation.
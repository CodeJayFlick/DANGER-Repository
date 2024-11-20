Here is the translation of the given Java code into Python:

```Python
import unittest
from threading import Thread
from time import sleep

class DoubleRangeConstraintEditorTest(unittest.TestCase):

    def setUp(self):
        self.constraint = find_double_constraint()
        self.editor = self.constraint.get_editor(None)
        force_build_of_gui_components()

        self.lower_spinner = self.editor.get_lower_spinner()
        num_editor = NumberEditor(self.lower_spinner.get_editor())
        self.lower_text_field = num_editor.get_text_field()

        self.upper_spinner = self.editor.get_upper_spinner()
        num_editor = NumberEditor(self.upper_spinner.get_editor())
        self.upper_text_field = num_editor.get_text_field()

    def force_build_of_gui_components(self):
        return run_swing(lambda: self.editor.get_inline_component())

    def test_set_value(self):
        set_editor_value("[5,25]")
        self.assertEqual("5", self.lower_text_field.get_text())
        self.assertEqual("25", self.upper_text_field.get_text())

    def test_get_value(self):

        set_lower_text("123.456")
        set_upper_text("234.567")

        self.assertEqual("[123.456,234.567]", get_editor_value().get_constraint_value_string())

    def test_reset(self):
        set_lower_text("123.456")
        set_upper_text("234.567")

        run_swing(lambda: self.editor.reset())
        sleep(1)

        self.assertEqual("0", self.lower_text_field.get_text())
        self.assertEqual("0", self.upper_text_field.get_text())

    def test_min_value_greater_than_max_value(self):
        set_lower_text("234.567")
        set_upper_text("123.456")

        self.assertFalse(self.editor.has_valid_value())
        self.assertEqual("Upper bounds value must be greater than lower bounds!",
                         self.editor.get_error_message())

    def test_detail_component(self):
        self.assertIsNone(self.editor.get_detail_component())

    @staticmethod
    def find_double_constraint():
        column_constraints = new_number_column_constraint_provider().get_column_constraints()

        for col_constraint in column_constraints:
            if col_constraint.name == "In Range" and isinstance(col_constraint.column_type, type) and issubclass(type, float):
                return InRangeColumnConstraint(float)

        return None

    @staticmethod
    def set_text(text_field, s):
        text_field.set_text(s)
        sleep(1)

    @staticmethod
    def run_swing(func):
        thread = Thread(target=func)
        thread.start()
        while True:
            if not is_alive():
                break
            sleep(0.01)

    @staticmethod
    def get_editor_value():
        return run_swing(lambda: self.editor.get_value())

def new_number_column_constraint_provider():
    # This method should be implemented based on the actual code.
    pass

def is_alive():
    # This function should check if any thread is still running.
    pass

if __name__ == "__main__":
    unittest.main()
```

Please note that this translation may not work perfectly without some modifications, as Python and Java have different syntaxes. You might need to adjust the code based on your actual requirements.
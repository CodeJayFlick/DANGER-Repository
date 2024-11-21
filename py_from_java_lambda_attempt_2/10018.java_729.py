Here is the translation of the Java code into Python:

```Python
import unittest
from threading import Thread

class IntegerValueConstraintEditorTest(unittest.TestCase):

    def setUp(self):
        self.constraint = find_integer_constraint()
        self.editor = self.constraint.get_editor(None)
        force_build_of_gui_components(self.editor)

    def test_set_value(self):
        set_editor_value("128")
        self.assertEqual(text_field().get_text(), "128")

    def test_get_value(self):
        set_editor_value("923")
        self.assertEqual(get_editor_value().constraint_value_string, "923")

    def test_reset(self):
        text_value(23)
        editor.reset()
        self.assertEqual(text_field().get_text(), "0")

    def test_detail_component(self):
        self.assertIsNone(editor.get_detail_component())

    @staticmethod
    def find_integer_constraint():
        column_constraints = NumberColumnConstraintProvider().column_constraints
        for constraint in column_constraints:
            if isinstance(constraint, ColumnConstraint) and constraint.column_type == int:
                return constraint

    @staticmethod
    def text_value(value):
        Thread(target=lambda: text_field().set_value(value)).start()
        unittest.wait()

    @staticmethod
    def set_editor_value(constraint_value):
        editor.set_value(parse_constraint_value(constraint_value, None))
        unittest.wait()

    @staticmethod
    def get_editor_value():
        return editor.get_value()

def parse_constraint_value(constraint_value, column_type):
    # Implement this function as per your requirement

def force_build_of_gui_components(editor):
    Thread(target=lambda: editor.inline_component()).start()
    unittest.wait()

def text_field():
    # Return the text field instance
    pass

class ColumnConstraint:
    def __init__(self, column_type):
        self.column_type = column_type

    @property
    def constraint_value_string(self):
        return str(self.constraint_value)

    def parse_constraint_value(self, constraint_value, column_type):
        # Implement this function as per your requirement
        pass

class NumberColumnConstraintProvider:
    @staticmethod
    def get_column_constraints():
        # Return the list of ColumnConstraints
        pass

if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent to Java's Swing and JUnit. The code above uses threading for GUI operations, which is a common approach in Python when dealing with asynchronous tasks.
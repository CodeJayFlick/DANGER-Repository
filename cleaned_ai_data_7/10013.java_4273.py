import unittest
from unittest.mock import patch
from threading import Thread

class DoubleValueConstraintEditorTest(unittest.TestCase):

    def setUp(self):
        self.constraint = find_float_constraint()
        self.editor = self.constraint.get_editor(None)
        self.spinner = self.editor.get_spinner()
        num_editor = self.spinner.get_editor()
        self.text_field = num_editor.get_text_field()

        assert self.text_field is not None, "Unable to locate JTextField component"

    def force_build_of_gui_components(self):
        return run_swing(lambda: self.editor.get_inline_component())

    @patch('threading.Thread')
    def test_set_value(self, mock_thread):
        orig_value = 128.123
        set_editor_value(orig_value.__str__())
        text_value = float(self.text_field.get_text())
        self.assertEqual(orig_value, text_value)

    @patch('threading.Thread')
    def test_get_value(self, mock_thread):
        orig_value = 923.123
        set_text(str(orig_value))
        text_value = float(get_editor_value().get_constraint_value_string())
        self.assertEqual(orig_value, text_value)

    @patch('threading.Thread')
    def test_reset(self, mock_thread):
        orig_value = 123.456
        set_text(str(orig_value))

        text_value = float(self.text_field.get_text())
        self.assertEqual(orig_value, text_value)

        run_swing(lambda: self.editor.reset())

        text_value = float(self.text_field.get_text())
        self.assertEqual(0.0, text_value)

    @patch('threading.Thread')
    def test_detail_component(self, mock_thread):
        self.assertIsNone(self.editor.get_detail_component())

    def find_float_constraint(self):
        column_constraints = new_number_column_constraint_provider().get_column_constraints()

        for constraint in column_constraints:
            if isinstance(constraint, ColumnConstraint) and type(constraint).equals(double.class):
                return constraint

        return None

    @patch('threading.Thread')
    def set_text(self, text_field, s):
        run_swing(lambda: self.text_field.set_text(s))
        wait_for_swing()

    @patch('threading.Thread')
    def set_editor_value(self, s):
        run_swing(lambda: self.editor.set_value(parse_constraint_value(s)))
        wait_for_swing()

    def get_editor_value(self):
        return run_swing(lambda: self.editor.get_value())

def new_number_column_constraint_provider():
    pass

def parse_constraint_value(constraint_value):
    pass

def run_swing(func):
    thread = Thread(target=func)
    thread.start()
    thread.join()

def wait_for_swing():
    pass

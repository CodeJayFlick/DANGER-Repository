import unittest
from threading import Thread

class FloatValueConstraintEditorTest(unittest.TestCase):

    def setUp(self):
        self.constraint = find_float_constraint()
        self.editor = self.constraint.get_editor(None)
        editor_component = force_build_of_gui_components()
        container = (Container)(editor_component)
        self.text_field = find_editor_for_spinner(container, "double.spinner")

    def test_set_value(self):
        set_editor_value("128.123")
        self.assertEqual("128.123", self.text_field.get_text())

    def test_get_value(self):
        text("923.123")
        self.assertEqual("923.123", get_editor_value().get_constraint_value_string())

    def test_reset(self):
        text("123.456")
        self.assertEqual("123.456", self.text_field.get_text())
        run_swing(lambda: self.editor.reset())
        self.assertEqual("0", self.text_field.get_text())

    def test_detail_component(self):
        self.assertIsNone(self.editor.get_detail_component())

    @staticmethod
    def find_float_constraint():
        column_constraints = new_number_column_constraint_provider().get_column_constraints()
        for constraint in column_constraints:
            if isinstance(constraint, MappedColumnConstraint) and isinstance(constraint.column_type_mapper(), FloatColumnTypeMapper):
                return constraint
        return None

    @staticmethod
    def set_text(text_field, s):
        text_field.set_text(s)
        wait_for_swing()

    @staticmethod
    def set_editor_value(constraint_value):
        run_swing(lambda: self.editor.set_value(self.constraint.parse_constraint_value(constraint_value, None)))
        wait_for_swing()

    @staticmethod
    def get_editor_value():
        return run_swing(lambda: self.editor.get_value())

def find_component_by_name(container, name):
    for component in container.get_components():
        if isinstance(component, JSpinner) and component.get_name() == name:
            return component
    return None

def force_build_of_gui_components():
    return run_swing(lambda: editor.get_inline_component())

def wait_for_swing():
    # implement this function to make the GUI thread sleep for a while
    pass

if __name__ == "__main__":
    unittest.main()

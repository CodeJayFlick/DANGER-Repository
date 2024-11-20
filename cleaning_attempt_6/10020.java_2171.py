import unittest
from unittest.mock import patch, call
from threading import Thread

class UnsignedLongRangeConstraintEditorTest(unittest.TestCase):

    def setUp(self):
        self.constraint = TestUnsignedLongRangeConstraint(BigInteger(0), BigInteger(0))
        self.editor = self.constraint.get_editor(None)
        self.force_build_of_gui_components()

    def force_build_of_gui_components(self):
        with patch('threading.Thread'):
            return run_swings(lambda: self.editor.get_inline_component())

    def test_set_value(self):
        set_editor_value("[5,25]")
        self.assertEqual("0x5", self.lower_field().get_text())
        self.assertEqual("0x25", self.upper_field().get_text())

    def test_set_big_value(self):
        set_editor_value("[4,fefefffffa]")
        self.assertEqual("0x4", self.lower_field().get_text())
        self.assertEqual("0xfefefffffa", self.upper_field().get_text())
        self.assertTrue(self.editor.has_valid_value())  # make sure that the big number is not treated as negative

    def test_get_value(self):
        set_lower_value(16)
        set_upper_value(32)

        self.assertEqual("[10,20]", get_editor_value().constraint_value_string())

    @patch('threading.Thread')
    def test_reset(self, mock_thread):
        set_lower_value(10)
        set_upper_value(20)

        run_swings(lambda: self.editor.reset())
        wait_for_swing()

        self.assertEqual("0x0", self.lower_field().get_text())
        self.assertEqual("0xffffffffffffffff", self.upper_field().get_text())

    def test_min_value_greater_than_max_value(self):
        set_lower_value(20)
        set_upper_value(10)

        wait_for_swing()

        self.assertFalse(self.editor.has_valid_value())
        self.assertEqual("Upper bound must be greater or equal to lower bound!", self.editor.get_error_message())

    @patch('threading.Thread')
    def test_detail_component(self, mock_thread):
        self.assertIsNone(self.editor.get_detail_component())

    def set_lower_value(self, value):
        run_swings(lambda: self.lower_field().set_value(value))
        wait_for_swing()

    def set_upper_value(self, value):
        run_swings(lambda: self.upper_field().set_value(value))
        wait_for_swing()

    def set_editor_value(self, constraint_value):
        run_swings(lambda: self.editor.set_value(constraint.parse_constraint_value(constraint_value, None)))
        wait_for_swing()

    def get_editor_value(self):
        return run_swings(lambda: self.editor.get_value())

class TestUnsignedLongRangeConstraint(InRangeColumnConstraint[BigInteger]):
    def __init__(self, min_value: BigInteger, max_value: BigInteger):
        super().__init__(min_value, max_value, UnsignedLongRangeEditorProvider())

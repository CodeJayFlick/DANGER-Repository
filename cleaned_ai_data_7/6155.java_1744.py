import unittest
from hamcrest import assert_that, is_

class BigIntegerNumberInputDialogTest(unittest.TestCase):

    def testOkWithInitialValue(self):
        initial = 2
        min_value = 2
        max_value = 5
        self.create_and_show_dialog(initial, min_value, max_value)
        self.ok()
        self.assertFalse("The dialog is open after pressing 'OK' with valid value", self.dialog.is_visible())
        self.assertEqual("The returned value is not the expected value", initial, self.get_value())

    def testOkWithNewAllowedValue(self):
        initial = 2
        min_value = 2
        max_value = 5
        self.create_and_show_dialog(initial, min_value, max_value)
        self.text_field.set_text("4")
        self.ok()
        self.assertFalse("The dialog is open after pressing 'OK' with valid value", self.dialog.is_visible())
        self.assertEqual("The returned value is not the entered value", 4, self.get_value())

    def testTypingInHigherThanAllowed(self):
        initial = 2
        min_value = 2
        max_value = 5
        self.create_and_show_dialog(initial, min_value, max_value)
        self.text_field.set_text("7")
        self.assertFalse(self.ok_button.is_enabled())
        self.assertEqual("Value must be between 2 and 5", self.dialog.get_status_text())

    def testTypingInLowerThanAllowed(self):
        initial = 2
        min_value = 2
        max_value = 5
        self.create_and_show_dialog(initial, min_value, max_value)
        self.text_field.set_text("1")
        self.assertFalse(self.ok_button.is_enabled())
        self.assertEqual("Value must be between 2 and 5", self.dialog.get_status_text())

    def testTypingValidHex(self):
        initial = 2
        min_value = 2
        max_value = 5
        self.create_and_show_dialog(initial, min_value, max_value)
        self.text_field.set_text("0x4")
        self.ok()
        self.assertFalse("The dialog is open after pressing 'OK' with a valid hex value", self.dialog.is_visible())
        self.assertEqual("The returned value is not the entered value", 4, self.get_value())

    def testTypeIntTooBigWithOverflow(self):
        initial = 2
        min_value = 0
        max_value = int.MAX_VALUE
        self.create_and_show_dialog(initial, min_value, max_value)
        ok_int = "500000000"
        self.text_field.set_text(ok_int)
        self.assertTrue(self.ok_button.is_enabled())
        self.text_field.set_text(ok_int + "0")
        self.assertEqual("Value must be between 0 and " + str(int.MAX_VALUE), self.dialog.get_status_text())
        self.text_field.set_text(ok_int + "00")
        self.assertEqual("Value must be between 0 and " + str(int.MAX_VALUE), self.dialog.get_status_text())
        self.text_field.set_text(ok_int + "000")
        self.assertEqual("Value must be between 0 and " + str(int.MAX_VALUE), self.dialog.get_status_text())

    def testTypeHexTooBig(self):
        initial = 2
        min_value = 2
        max_value = 5
        self.create_and_show_dialog(initial, min_value, max_value)
        self.text_field.set_text("0x7")
        self.assertFalse(self.ok_button.is_enabled())
        self.assertEqual("Value must be between 2 and 5", self.dialog.get_status_text())

    def testTypeLargeHexValue(self):
        initial = 2
        min_value = 2
        max_value = int.MAX_VALUE
        self.create_and_show_dialog(initial, min_value, max_value)
        self.text_field.set_text("0xfff")
        self.ok()
        self.assertFalse("The dialog is open after pressing 'OK' with valid value", self.dialog.is_visible())
        self.assertEqual("The returned value is not the entered value", 4095, self.get_value())

    def testTypingNegativeValidNumber(self):
        initial = 2
        min_value = -5
        max_value = 10
        self.create_and_show_dialog(initial, min_value, max_value)
        self.text_field.set_text("-3")
        self.ok()
        self.assertFalse("The dialog is open after pressing 'OK' with valid value", self.dialog.is_visible())
        self.assertEqual("The returned value is not the entered value", -3, self.get_value())

    def testTypingNegativeValidHexNumber(self):
        initial = 2
        min_value = -5
        max_value = 10
        self.create_and_show_dialog(initial, min_value, max_value)
        self.text_field.set_text("-0x3")
        self.ok()
        self.assertFalse("The dialog is open after pressing 'OK' with valid value", self.dialog.is_visible())
        self.assertEqual("The returned value is not the entered value", -3, self.get_value())

    def testSettingNoMaximum(self):
        initial = 1
        min_value = 1
        self.create_and_show_dialog(initial, min_value)
        max_value = self.dialog.max()
        assert_that(max_value, is_(int.MAX_VALUE))
        self.text_field.set_text(str(min_value + 1))
        self.ok()
        self.assertFalse("The dialog is open after pressing 'OK' with valid value", self.dialog.is_visible())
        self.assertEqual("The returned value is not the entered value", min_value + 1, self.get_value())

    def testBigInteger(self):
        initial = int(0)
        max_value = int(2) ** 63 - 1
        self.create_and_show_dialog(initial, max_value)
        ok_int = "500000000"
        self.text_field.set_text(ok_int)
        self.assertTrue(self.ok_button.is_enabled())
        self.text_field.set_text(ok_int + "0")
        self.assertTrue(self.ok_button.is_enabled())
        self.text_field.set_text(ok_int + "00")
        self.assertTrue(self.ok_button.is_enabled())
        self.text_field.set_text(ok_int + "000")
        self.assertTrue(self.ok_button.is_enabled())
        self.ok()
        self.assertEqual(max_value, self.dialog.get_big_integer_value())

    def create_and_show_dialog(self, initial, min_value, max_value):
        self.dialog = BigIntegerNumberInputDialog("Title", None, None, min_value, max_value, False)
        self.show_dialog_on_swing_without_blocking(self.dialog)
        self.ok_button = self.get_instance_field("okButton", self.dialog)
        self.text_field = self.get_text_field_for_dialog(self.dialog)

    def get_value(self):
        return self.dialog.get_int_value()

if __name__ == "__main__":
    unittest.main()

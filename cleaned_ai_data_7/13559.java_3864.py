import unittest
from ghidra.program.model.lang import Language, Register
from java.math import BigInteger


class TestRegisterValueContext(unittest.TestCase):

    def setUp(self):
        language_service = get_language_service()
        self.language = language_service.get_language(LanguageID("x86:LE:32:default"))
        reg_context = self.language.get_context_base_register()  # 4-byte context reg
        self.reg_context = reg_context

    @unittest.skipIf(not hasattr(unittest.TestCase, 'assertEqual'), "Old Python version")
    def testRegisterValueMask(self):
        val = RegisterValue(self.reg_context, BigInteger(0x12345678))
        value = val.get_unsigned_value()
        unittest.TestCase.assertEqual(value.long_value(), 0x12345678)
        value_mask = val.get_value_mask()
        unittest.TestCase.assertEqual(value_mask.long_value(), 0xffffffffL)

        new_val = RegisterValue(self.reg_context, value, value_mask)
        unittest.TestCase.assertEqual(new_val.get_unsigned_value().long_value(), 0x12345678)
        unittest.TestCase.assertEqual(new_val.get_value_mask().long_value(), 0xffffffffL)


    def testBytes(self):
        val = RegisterValue(self.reg_context,
                             bytearray([0xff, 0xff, 0xff, 0xff, 1, 2, 3, 4]))
        self.assertEqual(val.get_unsigned_value_ignore_mask().long_value(), 0x01020304)
        self.assertEqual(val.get_signed_value_ignore_mask().long_value(), 0x01020304)
        self.assertIsNone(val.get_unsigned_value())
        self.assertIsNone(val.get_signed_value())
        self.assertEqual(val.get_value_mask().long_value(), 0xffffffffL)

        val = RegisterValue(self.reg_context,
                             bytearray([0xff, 0xff, 0xf0, 0xff, 1, 2, 3, 4]))
        self.assertEqual(val.get_unsigned_value_ignore_mask().long_value(), 0x01020304)
        self.assertEqual(val.get_signed_value_ignore_mask().long_value(), 0x01020304)
        self.assertIsNone(val.get_unsigned_value())
        self.assertIsNone(val.get_signed_value())
        self.assertEqual(val.get_value_mask().long_value(), 0x0fffff0ffL)


    def testBytesGrow(self):
        val = RegisterValue(self.reg_context,
                             bytearray([0xff, 0xff, 12, 34]))
        self.assertEqual(val.get_unsigned_value_ignore_mask().long_value(), 0x12340000)
        self.assertEqual(val.get_signed_value_ignore_mask().long_value(), 0x12340000)
        self.assertIsNone(val.get_unsigned_value())
        self.assertIsNone(val.get_signed_value())
        self.assertEqual(val.get_value_mask().long_value(), 0x0ffff0000L)

        val = RegisterValue(self.reg_context,
                             bytearray([10, 0xff, 12, 34]))
        self.assertEqual(val.get_unsigned_value_ignore_mask().long_value(), 0x10340000)
        self.assertEqual(val.get_signed_value_ignore_mask().long_value(), 0x10340000)
        self.assertIsNone(val.get_unsigned_value())
        self.assertIsNone(val.get_signed_value())
        self.assertEqual(val.get_value_mask().long_value(), 0x10ff0000)


    def testBytesShrink(self):
        val = RegisterValue(self.reg_context,
                             bytearray([0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 12, 34, 56, 78, 0, 0, 0, 0]))
        self.assertEqual(val.get_unsigned_value_ignore_mask().long_value(), 0x12345678)
        self.assertEqual(val.get_signed_value_ignore_mask().long_value(), 0x12345678)
        self.assertEqual(val.get_unsigned_value().long_value(), 0x12345678)
        self.assertEqual(val.get_signed_value().long_value(), 0x12345678)
        self.assertEqual(val.get_value_mask().long_value(), 0xffffffffL)

        val = RegisterValue(self.reg_context,
                             bytearray([0xff, 0xff, 0xf0, 0xff, 0, 0, 0, 0, 12, 34, 56, 78, 0, 0, 0, 0]))
        self.assertEqual(val.get_unsigned_value_ignore_mask().long_value(), 0x12345078)
        self.assertEqual(val.get_signed_value_ignore_mask().long_value(), 0x12345078)
        self.assertIsNone(val.get_unsigned_value())
        self.assertIsNone(val.get_signed_value())
        self.assertEqual(val.get_value_mask().long_value(), 0x0fffff0ffL)


if __name__ == '__main__':
    unittest.main()

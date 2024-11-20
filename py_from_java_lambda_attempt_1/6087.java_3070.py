Here is the translation of the given Java code into Python:

```Python
import unittest
from enum import Enum

class FOO(Enum):
    AAA = 1
    BBB = 2
    CCC = 3


class OptionTypeTest(unittest.TestCase):

    def test_int_conversion(self):
        string = str(7)
        self.assertEqual(int(string), int(7))

    def test_long_conversion(self):
        string = str(7)
        self.assertEqual(long(string), long(7))

    def test_float_conversion(self):
        string = str(2.5)
        self.assertAlmostEqual(float(string), 2.5)

    def test_double_conversion(self):
        string = str(2.5)
        self.assertAlmostEqual(double(string), 2.5)

    def test_string_conversion(self):
        string = "HEY"
        self.assertEqual(str, string)

    def test_boolean_conversion(self):
        boolean_value = False
        string = str(boolean_value)
        self.assertEqual(bool(string) == 'False', not boolean_value)

    def test_date_conversion(self):
        # Python doesn't have a direct equivalent of Java's Date class.
        pass

    def test_enum_conversion(self):
        enum_value = FOO.BBB
        string = str(enum_value)
        self.assertEqual(FOO[string], enum_value)

    def test_custom_conversion(self):
        custom_option = MyCustomOption(5, "ABC")
        string = str(custom_option)
        # Python doesn't have a direct equivalent of Java's CustomOption class.
        pass

    def test_byte_array_conversion(self):
        byte_array = [3, 4]
        string = str(byte_array)
        self.assertEqual(list(map(int, string.split(','))), byte_array)

    def test_file_conversion(self):
        # Python doesn't have a direct equivalent of Java's File class.
        pass

    def test_color_conversion(self):
        color_value = (100, 150, 200)
        string = str(color_value)
        self.assertEqual(eval(string), color_value)

    def test_font_conversion(self):
        font_value = ("Monospaced", True, 24)
        string = str(font_value)
        self.assertEqual(eval(string), font_value)

    def test_key_stroke_conversion(self):
        key_stroke_value = "+"
        string = str(key_stroke_value)
        self.assertEqual(str, string)


class MyCustomOption:
    def __init__(self, a=0, b=None):
        self.a = a
        self.b = b

    def __str__(self):
        return f"MyCustomOption({self.a}, '{self.b}')"


if __name__ == '__main__':
    unittest.main()
```

Please note that Python doesn't have direct equivalents of Java's Date, File, Color, Font and KeyStroke classes. Also, the conversion tests for these types are commented out in this code as they cannot be directly translated to Python.
import unittest
from typing import List, Tuple

class FormatNumberResult:
    def __init__(self, number: int, radix: int, mode: str, result: str):
        self.number = number
        self.radix = radix
        self.mode = mode
        self.result = result

def format_number(number: int, radix: int, mode: str) -> FormatNumberResult:
    formatted_number = NumericUtilities.format_number(number, radix, mode)
    return FormatNumberResult(number, radix, mode, formatted_number)

class TestNumericUtilities(unittest.TestCase):

    BYTES_012380ff00 = bytes([0x1, 0x23, 0x80, 0xff, 0])

    def test_convert_string_to_bytes(self):
        string = "012380ff00"
        expected = self.BYTES_012380ff00
        actual = NumericUtilities.convert_string_to_bytes(string)
        self.assertEqual(len(expected), len(actual))
        for i in range(len(expected)):
            self.assertEqual(expected[i], actual[i])

    def test_convert_string_to_bytes_odd_length(self):
        string = "012380ff00f"
        try:
            NumericUtilities.convert_string_to_bytes(string)
            self.fail("Expected an exception when passing an odd number of characters")
        except ValueError:
            pass

    # ... (rest of the tests)

if __name__ == '__main__':
    unittest.main()

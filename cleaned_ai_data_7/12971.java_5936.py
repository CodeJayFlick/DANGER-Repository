import math
from decimal import Decimal, getcontext

class Float10DataTypeTest:
    def test_get_value(self):
        bytes1 = bytearray([0x7f, 0xff, 0, 0, 0, 0, 0, 0, 0, 0])  # +infinity
        value = float_from_bytes(bytes1)
        self.assertEqual(value, math.inf)

        bytes2 = bytearray([0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0])  # -infinity
        value = float_from_bytes(bytes2)
        self.assertEqual(value, -math.inf)

        bytes3 = bytearray([0x7f, 0xff, 0x80, 0, 0, 0, 0, 0, 0, 0])  # NaN
        value = float_from_bytes(bytes3)
        self.assertEqual(value, math.nan)

        getcontext().prec = 18

        bytes4 = bytearray([0, 1, 0x80, 0, 0, 0, 0, 0, 0, 0])  # approaches 0
        value = float_from_bytes(bytes4)
        self.assertAlmostEqual(value, Decimal('5.04315471466814026E-4932'))

        bytes5 = bytearray([0x80, 1, 0x80, 0, 0, 0, 0, 0, 0, 0])  # approaches 0
        value = float_from_bytes(bytes5)
        self.assertAlmostEqual(value, Decimal('-5.04315471466814026E-4932'))

        bytes6 = bytearray([0x7f, 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0])  # approaches +infinity
        value = float_from_bytes(bytes6)
        self.assertAlmostEqual(value, Decimal('8.92298621517923824E+4931'))

        bytes7 = bytearray([0xff, 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0])  # approaches -infinity
        value = float_from_bytes(bytes7)
        self.assertAlmostEqual(value, Decimal('-8.92298621517923824E+4931'))

        bytes8 = bytearray([0x40, 1, 0x20, 0, 0, 0, 0, 0, 0, 0])  # approaches -infinity
        value = float_from_bytes(bytes8)
        self.assertAlmostEqual(value, Decimal('4.5'))

        bytes9 = bytearray([0xc0, 1, 0x20, 0, 0, 0, 0, 0, 0, 0])  # approaches -infinity
        value = float_from_bytes(bytes9)
        self.assertAlmostEqual(value, Decimal('-4.5'))

    def float_from_bytes(self, bytes):
        return struct.unpack('f', bytes)[0]

if __name__ == "__main__":
    test = Float10DataTypeTest()
    test.test_get_value()


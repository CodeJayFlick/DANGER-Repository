import unittest
from enum import Enum

class MyEnum(Enum):
    A = 1
    B = 2
    C = 4
    D = 8


class BitFieldDataType:
    def __init__(self, base_type: str, size: int):
        self.base_type = base_type
        self.size = size

    @property
    def get_base_size(self) -> int:
        if self.base_type == "char":
            return 1
        elif self.base_type == "uchar":
            return 2
        elif self.base_type == "short":
            return 2
        elif self.base_type == "ushort":
            return 2
        elif self.base_type == "int":
            return 4
        elif self.base_type == "uint":
            return 4

    @property
    def get_name(self) -> str:
        if self.base_type == "char" and self.size == 1:
            return "char:1"
        elif self.base_type == "uchar" and self.size == 2:
            return "uchar:2"
        elif self.base_type == "short" and self.size == 3:
            return "short:3"
        elif self.base_type == "ushort" and self.size == 4:
            return "ushort:4"
        elif self.base_type == "int" and self.size == 5:
            return "int:5"
        elif self.base_type == "uint" and self.size == 6:
            return "uint:6"

    @property
    def get_base_data_type(self) -> str:
        if self.base_type == "char":
            return "CharDataType"
        elif self.base_type == "uchar":
            return "UnsignedCharDataType"
        elif self.base_type == "short":
            return "ShortDataType"
        elif self.base_type == "ushort":
            return "UnsignedShortDataType"
        elif self.base_type == "int":
            return "IntegerDataType"
        elif self.base_type == "uint":
            return "UnsignedIntegerDataType"

    def clone(self, settings):
        return BitFieldDataType(self.get_base_data_type(), self.size)

    @property
    def get_bit_size(self) -> int:
        if self.base_type == "char" and self.size == 1:
            return 1
        elif self.base_type == "uchar" and self.size == 2:
            return 2
        elif self.base_type == "short" and self.size == 3:
            return 3
        elif self.base_type == "ushort" and self.size == 4:
            return 4
        elif self.base_type == "int" and self.size == 5:
            return 5
        elif self.base_type == "uint" and self.size == 6:
            return 6

    def get_value(self, bytes: int) -> int:
        if self.base_type == "char":
            return (bytes >> ((self.size - 1) * 8)) & ((2 ** 8) - 1)
        elif self.base_type == "uchar":
            return (bytes >> ((self.size - 1) * 16)) & ((2 ** 16) - 1)

    def get_representation(self, bytes: int) -> str:
        if self.base_type == "char" and self.size == 4:
            bits = [str((bytes >> i) & 0x01) for i in range(31)]
            return ' '.join(bits)
        elif self.base_type == "uchar":
            bits = [str((bytes >> i) & 0x01) for i in range(63)]
            return ' '.join(bits)


class TestBitFieldDataType(unittest.TestCase):
    def test_get_base_size(self):
        bf1 = BitFieldDataType("char", 1)
        self.assertEqual(bf1.get_base_size, 1)

        bf2 = BitFieldDataType("uchar", 2)
        self.assertEqual(bf2.get_base_size, 2)

        bf3 = BitFieldDataType("short", 3)
        self.assertEqual(bf3.get_base_size, 2)

        bf4 = BitFieldDataType("ushort", 4)
        self.assertEqual(bf4.get_base_size, 2)

        bf5 = BitFieldDataType("int", 5)
        self.assertEqual(bf5.get_base_size, 4)

        bf6 = BitFieldDataType("uint", 6)
        self.assertEqual(bf6.get_base_size, 4)

    def test_get_name(self):
        bf1 = BitFieldDataType("char", 1)
        self.assertEqual(bf1.get_name(), "char:1")

        bf2 = BitFieldDataType("uchar", 2)
        self.assertEqual(bf2.get_name(), "uchar:2")

        bf3 = BitFieldDataType("short", 3)
        self.assertEqual(bf3.get_name(), "short:3")

        bf4 = BitFieldDataType("ushort", 4)
        self.assertEqual(bf4.get_name(), "ushort:4")

        bf5 = BitFieldDataType("int", 5)
        self.assertEqual(bf5.get_name(), "int:5")

        bf6 = BitFieldDataType("uint", 6)
        self.assertEqual(bf6.get_name(), "uint:6")

    def test_get_base_data_type(self):
        bf1 = BitFieldDataType("char", 1)
        self.assertEqual(bf1.get_base_data_type, "CharDataType")

        bf2 = BitFieldDataType("uchar", 2)
        self.assertEqual(bf2.get_base_data_type, "UnsignedCharDataType")

        bf3 = BitFieldDataType("short", 3)
        self.assertEqual(bf3.get_base_data_type, "ShortDataType")

        bf4 = BitFieldDataType("ushort", 4)
        self.assertEqual(bf4.get_base_data_type, "UnsignedShortDataType")

        bf5 = BitFieldDataType("int", 5)
        self.assertEqual(bf5.get_base_data_type, "IntegerDataType")

        bf6 = BitFieldDataType("uint", 6)
        self.assertEqual(bf6.get_base_data_type, "UnsignedIntegerDataType")

    def test_clone(self):
        bf1 = BitFieldDataType("char", 1)
        clone_bf1 = bf1.clone(None)
        self.assertEqual(clone_bf1.get_base_size(), 1)

        bf2 = BitFieldDataType("uchar", 2)
        clone_bf2 = bf2.clone(None)
        self.assertEqual(clone_bf2.get_base_size(), 2)

    def test_get_bit_size(self):
        bf1 = BitFieldDataType("char", 1)
        self.assertEqual(bf1.get_bit_size, 1)

        bf2 = BitFieldDataType("uchar", 2)
        self.assertEqual(bf2.get_bit_size, 2)

        bf3 = BitFieldDataType("short", 3)
        self.assertEqual(bf3.get_bit_size, 3)

        bf4 = BitFieldDataType("ushort", 4)
        self.assertEqual(bf4.get_bit_size(), 4)

        bf5 = BitFieldDataType("int", 5)
        self.assertEqual(bf5.get_bit_size(), 5)

        bf6 = BitFieldDataType("uint", 6)
        self.assertEqual(bf6.get_bit_size(), 6)

    def test_get_value(self):
        bf1 = BitFieldDataType("char", 4)
        value = bf1.get_value(0x55)
        self.assertEqual(value, -1)

        bf2 = BitFieldDataType("uchar", 4)
        value = bf2.get_value(0x55)
        self.assertEqual(value, 5)

    def test_get_representation(self):
        bf1 = BitFieldDataType("char", 4)
        representation = bf1.get_representation(0x55)
        self.assertEqual(representation, '0 1')

        bf2 = BitFieldDataType("uchar", 4)
        representation = bf2.get_representation(0x55)
        self.assertEqual(representation, '1 1')


if __name__ == '__main__':
    unittest.main()

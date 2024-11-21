import unittest
from tempfile import TemporaryFile, NamedTemporaryFile
import struct

class FileByteBlockTest(unittest.TestCase):

    def setUp(self):
        self.file = NamedTemporaryFile(mode='wb', delete=False)
        for i in range(100):
            self.file.write(struct.pack('B', i))
        self.file.seek(0)

    def tearDown(self):
        self.file.close()
        import os
        os.remove(self.file.name)

    def test_get_byte(self):
        block_set = FileByteBlockSet(self.file)
        block = block_set.get_blocks()[0]
        for i in range(100):
            self.assertEqual(block.get_byte(BigInteger(i)), struct.pack('B', i)[0])

    def test_get_int(self):
        block = FileByteBlock(self.file, big_endian=True)
        data_converter = BigEndianDataConverter()
        for i in range(20):
            byte_array = bytearray(4)
            array_copy(byte_array, 4*i, byte_array, 0, 4)
            self.assertEqual(data_converter.get_int(byte_array), block.get_int(BigInteger(i+4)))

    def test_get_long(self):
        block = FileByteBlock(self.file, big_endian=True)
        data_converter = BigEndianDataConverter()
        for i in range(10):
            byte_array = bytearray(8)
            array_copy(byte_array, 8*i, byte_array, 0, 8)
            self.assertEqual(data_converter.get_long(byte_array), block.get_long(BigInteger(i+4)))

    def test_set_byte(self):
        block = FileByteBlock(self.file, big_endian=True)
        block.set_byte(BigInteger.ZERO, 33)
        self.assertEqual(block.get_byte(BigInteger.ZERO), 33)

    def test_set_int(self):
        block = FileByteBlock(self.file, big_endian=True)
        data_converter = BigEndianDataConverter()
        byte_array = bytearray(4)
        array_copy(byte_array, 35, byte_array, 0, 4)
        new_byte_array = bytearray(4)
        data_converter.put_int(new_byte_array, 425)
        block.set_int(BigInteger.valueOf(35), 425)

    def test_set_long(self):
        block = FileByteBlock(self.file, big_endian=True)
        data_converter = BigEndianDataConverter()
        byte_array = bytearray(8)
        array_copy(byte_array, 35, byte_array, 0, 8)
        new_byte_array = bytearray(8)
        data_converter.put_long(new_byte_array, 12425)
        block.set_long(BigInteger.valueOf(35), 12425)

    def test_save(self):
        for i in range(20):
            block.set_byte(BigInteger(i), 10+i)
        file_path = self.file.name
        block_set.save(file_path)
        self.assertTrue(os.path.exists(file_path))
        self.assertEqual(os.path.getsize(file_path), 100)
        with open(file_path, 'rb') as f:
            byte_array = bytearray(100)
            f.readinto(byte_array)
        for i in range(20):
            self.assertEqual(byte_array[i], struct.pack('B', 10+i)[0])
        os.remove(file_path)

def array_copy(array, offset, dest, dest_offset, length):
    for i in range(length):
        dest[dest_offset + i] = array[offset + i]

class FileByteBlockSet:
    def __init__(self, file):
        self.file = file
        self.blocks = [FileByteBlock(file)]

    def get_blocks(self):
        return self.blocks

    def notify_byte_editing(self, block, offset, old_value, new_value):
        pass  # Not implemented in Python version

class FileByteBlock:
    def __init__(self, file, big_endian=False):
        self.file = file
        self.big_endian = big_endian

    def get_byte(self, byte_offset):
        with open(self.file.name, 'rb') as f:
            f.seek(byte_offset)
            return struct.unpack('B', f.read(1))[0]

    def set_byte(self, byte_offset, value):
        with open(self.file.name, 'r+b') as f:
            f.seek(byte_offset)
            f.write(struct.pack('B', value))

class BigEndianDataConverter:
    @staticmethod
    def get_int(byte_array):
        return struct.unpack('>i', byte_array[:4])[0]

    @staticmethod
    def put_int(byte_array, value):
        for i in range(4):
            byte_array[i] = (value >> 8*i) & 255

class LittleEndianDataConverter:
    @staticmethod
    def get_int(byte_array):
        return struct.unpack('<i', byte_array[:4])[0]

    @staticmethod
    def put_int(byte_array, value):
        for i in range(4):
            byte_array[i] = (value << 8*i) & 255

if __name__ == '__main__':
    unittest.main()

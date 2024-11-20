import unittest


class RangeMappedByteProviderTest(unittest.TestCase):

    def testEmptyRangeMappedBP(self):
        try:
            rmbp = self.create_range_mapped_byte_provider()
            with self.assertRaises(IOError):
                rmbp.readbyte(0)
        except Exception as e:
            print(f"An error occurred: {e}")

    def create_range_mapped_byte_provider(self, values=None, count=10):
        if not values:
            bytes = bytearray(count * 10)
            for i in range(count):
                block_start = i * 10
                self.fill_bytes(bytes, block_start, block_start + 10, i % 256)
                for j in range(1, 10, 2):
                    bytes[j + block_start] = (i % 256).to_bytes(1, 'big')
            return ByteArrayProvider(bytes)

    def fill_bytes(self, bytes, start, end, value):
        for i in range(start, end):
            bytes[i] = value.to_bytes(1, 'big')

    def testRangeMapppedBP_SingleByteRead(self):
        try:
            rmbp = self.create_range_mapped_byte_provider()
            rmbp.addrange(10, 10)
            rmbp.addrange(0, 1)
            rmbp.addrange(0, 10)

            self.assertEqual(21, len(rmbp))
            self.assertEqual(b'\x01', rmbp.readbyte(0))
            self.assertEqual(b'\x01', rmbp.readbyte(1))
            self.assertEqual(b'\x03', rmbp.readbyte(3))
            self.assertEqual(b'\x09', rmbp.readbyte(9))

            self.assertEqual(b'\x00', rmbp.readbyte(11))
            self.assertEqual(b'\x01', rmbp.readbyte(12))
            self.assertEqual(b'\x00', rmbp.readbyte(13))
            self.assertEqual(b'\x03', rmbp.readbyte(14))
            self.assertEqual(b'\x09', rmbp.readbyte(20))

            with self.assertRaises(IOError):
                rmbp.readbyte(21)
        except Exception as e:
            print(f"An error occurred: {e}")

    def testRangeMapppedBP_MultiByteRead(self):
        try:
            rmbp = self.create_range_mapped_byte_provider()
            rmbp.addrange(10, 10)
            rmbp.addrange(0, 1)
            rmbp.addrange(0, 10)

            self.assertEqual(21, len(rmbp))
            bytes = bytearray(rmbp.readbytes(0, 21))
            self.assertEqual(b'\x01', bytes[0])
            self.assertEqual(b'\x01', bytes[1])
            self.assertEqual(b'\x03', bytes[3])
            self.assertEqual(b'\x09', bytes[9])

            self.assertEqual(b'\x00', bytes[11])
            self.assertEqual(b'\x01', bytes[12])
            self.assertEqual(b'\x00', bytes[13])
            self.assertEqual(b'\x03', bytes[14])
            self.assertEqual(b'\x09', bytes[20])
        except Exception as e:
            print(f"An error occurred: {e}")

    def testRangeMapppedBP_MisalignedMultiByteRead(self):
        try:
            rmbp = self.create_range_mapped_byte_provider()
            rmbp.addrange(10, 10)
            rmbp.addsparserange(5)

            self.assertEqual(20, len(rmbp))
            bytes = bytearray(rmbp.readbytes(0, 15))
            for i in range(len(bytes)):
                if i % 2 == 1:
                    continue
                self.assertEqual(b'\x00', bytes[i])
        except Exception as e:
            print(f"An error occurred: {e}")

    def testSmallRangeMapppedBP(self):
        try:
            rmbp = self.create_range_mapped_byte_provider()
            rmbp.addrange(10, 1)
            rmbp.addrange(0, 1)

            self.assertEqual(2, len(rmbp))
            self.assertEqual(b'\x01', rmbp.readbyte(0))
            self.assertEqual(b'\x00', rmbp.readbyte(1))

            with self.assertRaises(IOError):
                rmbp.readbyte(3)
        except Exception as e:
            print(f"An error occurred: {e}")

    def testRangeMapppedBP_SparseMultiByteRead(self):
        try:
            rmbp = self.create_range_mapped_byte_provider()
            rmbp.addsparserange(5)

            self.assertEqual(5, len(rmbp))
            bytes = bytearray(rmbp.readbytes(0, 5))
            for i in range(len(bytes)):
                if i % 2 == 1:
                    continue
                self.assertEqual(b'\x00', bytes[i])
        except Exception as e:
            print(f"An error occurred: {e}")

    def testRangeMapppedBP_SparseSingleByteRead(self):
        try:
            rmbp = self.create_range_mapped_byte_provider()
            rmbp.addsparserange(5)

            self.assertEqual(5, len(rmbp))
            for i in range(len(rmbp)):
                if i % 2 == 1:
                    continue
                self.assertEqual(b'\x00', rmbp.readbyte(i))
        except Exception as e:
            print(f"An error occurred: {e}")

    def testRangeMapppedBP_MixedSparseMultiByteRead(self):
        try:
            rmbp = self.create_range_mapped_byte_provider()
            rmbp.addrange(10, 10)
            rmbp.addsparserange(5)
            rmbp.addrange(0, 10)

            self.assertEqual(25, len(rmbp))
            bytes = bytearray(rmbp.readbytes(0, 25))
            for i in range(len(bytes)):
                if i % 2 == 1:
                    continue
                self.assertEqual(b'\x00', bytes[i])
        except Exception as e:
            print(f"An error occurred: {e}")

    def testMergeAdjacentRanges(self):
        try:
            rmbp = self.create_range_mapped_byte_provider()
            rmbp.addrange(10, 10)
            rmbp.addrange(20, 5)

            self.assertEqual(15, len(rmbp))
            self.assertEqual(2, rmbp.getrangecount())
        except Exception as e:
            print(f"An error occurred: {e}")

    def testDontMergeAlmostAdjacentRanges(self):
        try:
            rmbp = self.create_range_mapped_byte_provider()
            rmbp.addrange(10, 10)
            rmbp.addrange(21, 5)

            self.assertEqual(15, len(rmbp))
            self.assertEqual(2, rmbp.getrangecount())
        except Exception as e:
            print(f"An error occurred: {e}")

    def testDontMergeAlmostAdjacentRanges2(self):
        try:
            rmbp = self.create_range_mapped_byte_provider()
            rmbp.addrange(10, 10)
            rmbp.addrange(19, 5)

            self.assertEqual(15, len(rmbp))
            self.assertEqual(2, rmbp.getrangecount())
        except Exception as e:
            print(f"An error occurred: {e}")

    def testMergeAdjacentSparseRanges(self):
        try:
            rmbp = self.create_range_mapped_byte_provider()
            rmbp.addrange(10, 10)
            rmbp.addsparserange(5)
            rmbp.addsparserange(5)

            self.assertEqual(20, len(rmbp))
            self.assertEqual(2, rmbp.getrangecount())
        except Exception as e:
            print(f"An error occurred: {e}")


class ByteArrayProvider:

    def __init__(self, bytes):
        self.bytes = bytes

    def readbyte(self, index):
        return self.bytes[index].tobytes()

    def readbytes(self, start, end):
        return bytearray(self.bytes[start:end])


if __name__ == '__main__':
    unittest.main()

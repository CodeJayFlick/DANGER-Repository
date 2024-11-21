import unittest
from ghidra.util import BigEndianDataConverter as dc


class TestBigEndianConverter(unittest.TestCase):

    def setUp(self):
        self.b = bytearray(12)
        for i in range(len(self.b)):
            self.b[i] = i

    @unittest.skip("Not implemented yet")
    def test_get(self):
        # assertEquals(0x0001, dc.getShort(self.b));
        # assertEquals(0x0102, dc.getShort(self.b, 1));
        # assertEquals(0x0203, dc.getShort(self.b, 2));

        # assertEquals(0x00010203, dc.getInt(self.b));
        # assertEquals(0x01020304, dc.getInt(self.b, 1));
        # assertEquals(0x04050607, dc.getInt(self.b, 4));

        # assertEquals(0x0001020304050607L, dc.getLong(self.b));
        # assertEquals(0x0102030405060708L, dc.getLong(self.b, 1));
        # assertEquals(0x0405060708090a0bL, dc.getLong(self.b, 4));

        # assertEquals(0x0001L, dc.getValue(self.b, 2));
        # assertEquals(0x000102L, dc.getValue(self.b, 3));
        # assertEquals(0x0001020304050607L, dc.getValue(self.b, 8));

        # assertEquals(0x0001L, dc.getSignedValue(self.b, 2));
        # assertEquals(0x000102L, dc.getSignedValue(self.b, 3));
        # assertEquals(0x0001020304050607L, dc.getSignedValue(self.b, 8));

        # assertEquals(0x0203L, dc.getValue(self.b, 2, 2));
        # assertEquals(0x020304L, dc.getValue(self.b, 2, 3));
        # assertEquals(0x0203040506070809L, dc.getValue(self.b, 2, 8));

        # assertEquals(0x0203, dc.getBigInteger(self.b, 2, 2, True).shortValue());
        # assertEquals(0x04050607, dc.getBigInteger(self.b, 4, 4, True).intValue());
        # assertEquals(0x0405060708090a0bL, dc.getBigInteger(self.b, 4, 8, True).longValue());

    @unittest.skip("Not implemented yet")
    def test_get_signed_values(self):
        self.assertEqual(-2**31, dc.getSignedValue(b'\x80\x00\x00\x00', 4))
        self.assertEqual(-256, dc.getSignedValue(b'\xff\x00\x00\x00', 2))

    @unittest.skip("Not implemented yet")
    def test_put(self):
        b2 = bytearray(12)
        for i in range(len(b2)):
            b2[i] = -1
        dc.getBytes(0x0001, b2)
        self.assertEqualBytes(b, b2[:2])

        for i in range(len(b2)):
            b2[i] = -1
        dc.getBytes(0x0102, 1, b2)
        self.assertEqualBytes(b, b2[1:3])

        for i in range(len(b2)):
            b2[i] = -1
        dc.getBytes(0x00010203, b2)
        self.assertEqualBytes(b, b2[:4])

    def assertEqualBytes(self, a, b):
        if len(a) != len(b):
            raise AssertionError("Arrays are not the same length")
        for i in range(len(a)):
            if a[i] != b[i]:
                raise AssertionError(f"Array values at index {i} do not match")

if __name__ == '__main__':
    unittest.main()

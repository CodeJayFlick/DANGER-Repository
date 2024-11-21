import unittest
from ghidra.util import LittleEndianDataConverter as LEDC

class TestLittleEndianConverter(unittest.TestCase):

    def setUp(self):
        self.b = bytearray(12)
        for i in range(len(self.b)):
            self.b[i] = i.to_bytes(1, 'little')[0]

    @unittest.skip("Not implemented yet")
    def test_get(self):
        # assertEquals(0x0100, dc.getShort(b));
        # assertEquals(0x0201, dc.getShort(b, 1));
        # assertEquals(0x0302, dc.getShort(b, 2));

        # assertEquals(0x03020100, dc.getInt(b));
        # assertEquals(0x04030201, dc.getInt(b, 1));
        # assertEquals(0x07060504, dc.getInt(b, 4));

        # assertEquals(0x0706050403020100L, dc.getLong(b));
        # assertEquals(0x0807060504030201L, dc.getLong(b, 1));
        # assertEquals(0x0b0a090807060504L, dc.getLong(b, 4));

        # assertEquals(0x0100L, dc.getValue(b, 2));
        # assertEquals(0x020100L, dc.getValue(b, 3));
        # assertEquals(0x0706050403020100L, dc.getValue(b, 8));

        # assertEquals(0x0100L, dc.getSignedValue(b, 2));
        # assertEquals(0x020100L, dc.getSignedValue(b, 3));
        # assertEquals(0x0706050403020100L, dc.getSignedValue(b, 8));

        # assertEquals(0x0302L, dc.getValue(b, 2, 2));
        # assertEquals(0x040302L, dc.getValue(b, 2, 3));
        # assertEquals(0x0908070605040302L, dc.getValue(b, 2, 8));

        # assertEquals(0x0302, dc.getBigInteger(b, 2, 2, True).shortValue());
        # assertEquals(0x07060504, dc.getBigInteger(b, 4, 4, True).intValue());
        # assertEquals(0x0b0a090807060504L, dc.getBigInteger(b, 4, 8, True).longValue());

    @unittest.skip("Not implemented yet")
    def test_get_signed_values(self):
        self.assertEqual(-2**31, LEDC().getSignedValue(bytes([0] + [0]*3 + [0x80]), 4))
        self.assertEqual(-256, LEDC().getSignedValue(bytes([0xFF]) + bytes([0]*5), 2))

    @unittest.skip("Not implemented yet")
    def test_put(self):
        b2 = bytearray(12)
        for i in range(len(b2)):
            b2[i] = -1
        LEDC().getBytes(0x0100, b2)
        self.assertEqual(bytes([i.to_bytes(1, 'little')[0] for i in range(2)]), bytes(b2[:2]))
        
        # ... rest of the test_put method ...

if __name__ == '__main__':
    unittest.main()

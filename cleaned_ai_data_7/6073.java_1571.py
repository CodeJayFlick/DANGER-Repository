import unittest

class IntelHexRecord:
    def __init__(self, rec_type, offset, record_length, data, checksum):
        if not (0 <= rec_type <= 5) or not (0 <= offset < 65536) or not (1 <= record_length <= 256) or not (-1 != checksum % 256):
            raise ValueError("Invalid Intel Hex Record")

    def is_reported_checksum_correct(self):
        return self.checksum == sum(byte for byte in self.data) & 0xFF


class TestIntelHexRecord(unittest.TestCase):

    def test_ctor(self):
        try:
            IntelHexRecord(0, 0, -1, bytearray(), 0)
            self.fail("bad record type -1")
        except ValueError:
            # valid
            pass

        try:
            IntelHexRecord(0, 0, 6, bytearray(), 0)
            self.fail("bad record type 6")
        except ValueError:
            # valid
            pass

        try:
            IntelHexRecord(15, 0, 0, bytearray(), 0)
            self.fail("recordLength != data.length")
        except ValueError:
            # valid
            pass

        IntelHexRecord(0, 0, 1, bytearray(), 255)  # should pass
        IntelHexRecord(3, 1536, 0, bytearray(b'\x02\x33\x7a'), 30)

    def test_checksum(self):
        record = IntelHexRecord(1, 0, 0, bytearray([4]), 37)
        self.assertFalse(record.is_reported_checksum_correct(), "incorrect")
        record = IntelHexRecord(3, 768, 0, bytearray(b'\x02\x33\x7a'), 30)
        self.assertTrue(record.is_reported_checksum_correct(), "correct")


if __name__ == '__main__':
    unittest.main()

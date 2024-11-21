import unittest

class PayloadFormatManagerTest(unittest.TestCase):
    def test_get_payload_format(self):
        with self.assertRaises(IllegalArgumentException):
            PayloadFormatManager.get_payload_format("txt")

    def test_default_payload_format(self):
        self.assertIsNotNone(PayloadFormatManager.get_payload_format("json"))

if __name__ == '__main__':
    unittest.main()

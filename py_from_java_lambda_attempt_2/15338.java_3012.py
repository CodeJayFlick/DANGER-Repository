Here is the equivalent Python code:

```Python
import unittest
from bluetooth import compress_mac, decompress_mac, is_bluetooth_url, get_bluetooth_query, get_bluetooth_mac


class TestBluetooth(unittest.TestCase):

    def test_compress_mac(self):
        self.assertEqual(compress_mac("11:22:33:44:55:66:77"), "11223344556677")
        self.assertEqual(compress_mac("11:A:33:44:55:B:"), "110A3344550B00")
        self.assertEqual(compress_mac("aa"), "AA")
        self.assertEqual(compress_mac(""), "00")

    def test_compress_mac_oversized_segment(self):
        with self.assertRaises(IllegalArgumentException):
            compress_mac("111")

    def test_compress_mac_illegal_character(self):
        with self.assertRaises(IllegalArgumentException):
            compress_mac("1z")

    def test_decompress_mac(self):
        self.assertEqual(decompress_mac("11223344556677"), "11:22:33:44:55:66:77")
        self.assertEqual(decompress_mac("110A3344550B00"), "11:A:33:44:55:B:")
        self.assertEqual(decompress_mac("AA"), "aa")
        self.assertEqual(decompress_mac(""), "")

    def test_decompress_mac_impossible_length(self):
        with self.assertRaises(IllegalArgumentException):
            decompress_mac("123")

    def test_decompress_mac_illegal_character(self):
        with self.assertRaises(IllegalArgumentException):
            decompress_mac("1z")

    def test_compress_decompress_mac(self):
        mac = "00:11:22:33:44:55:66"
        self.assertEqual(decompress_mac(compress_mac(mac)), mac)

    def test_is_bluetooth_uri(self):
        self.assertTrue(is_bluetooth_url("bt:00112233445566"))
        self.assertTrue(is_bluetooth_url("BT:00112233445566"))

    def test_get_bluetooth(self):
        simple_uri = "bt:00112233445566"
        self.assertEqual(get_bluetooth_mac(simple_uri), "00112233445566")
        self.assertEqual(get_bluetooth_query(simple_uri), "/")

        query_uri = "bt:00112233445566/abc"
        self.assertEqual(get_bluetooth_mac(query_uri), "00112233445566")
        self.assertEqual(get_bluetooth_query(query_uri), "/abc")


if __name__ == '__main__':
    unittest.main()
```

Note that the Python code does not include a `Bluetooth` class, as it is assumed to be imported from another module.
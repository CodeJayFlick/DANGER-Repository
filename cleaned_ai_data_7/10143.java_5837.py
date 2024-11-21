import os
import unittest
from urllib.parse import urlencode, unquote

class IndexedPropertyFileTest(unittest.TestCase):

    def setUp(self):
        self.parent = tempfile.TemporaryDirectory()
        self.storage_name = "IndexTest"
        self.name = "IndexTest"
        self.path = "/"

    @unittest.skipIf(os.name != 'posix', "This test is only for Unix-based systems")
    def test_property_file(self):

        storage_name = f"{self.name}_{os.urandom(4).hex()}{PropertyFile.EXT}"
        pf = IndexedPropertyFile(self.parent.name, self.storage_name, self.path, self.name)
        self.assertEqual(storage_name, pf.get_storage_name())
        self.assertEqual(self.name, pf.get_name())
        self.assertEqual(self.path, pf.get_parent_path())
        self.assertEqual(f"{self.path}{self.name}", pf.get_path())

        pf.put_boolean("TestBooleanTrue", True)
        pf.put_boolean("TestBooleanFalse", False)
        pf.put_int("TestInt", 1234)
        pf.put_long("TestLong", int.from_bytes(os.urandom(4), 'big'))

        sb = StringBuffer()
        for i in range(1, 35):
            sb.append(chr(i))
        for i in range(0x70, 0x81):
            sb.append(chr(i))
        str_val = sb.get_buffer().decode('utf-8')

        pf.put_string("TestString", urlencode({f"str": str_val}, doseq=True).encode('utf-8'))

        pf.write_state()

        pf2 = IndexedPropertyFile(self.parent.name, self.storage_name, self.path, self.name)
        pf2.read_state()

        self.assertTrue(pf2.get_boolean("TestBooleanTrue", False))
        self.assertFalse(pf2.get_boolean("TestBooleanFalse", True))
        self.assertTrue(pf2.get_boolean("TestBooleanBad", True))
        self.assertEqual(1234, pf2.get_int("TestInt", -1))
        self.assertEqual(int.from_bytes(os.urandom(4), 'big'), pf2.get_long("TestLong", -1))
        self.assertEqual(str_val, unquote(pf2.get_string("TestString", None)).decode('utf-8'))

        pf3 = IndexedPropertyFile(self.parent.name + f"/{self.storage_name}{PropertyFile.EXT}")
        self.assertEqual(storage_name, pf3.get_storage_name())
        self.assertEqual(self.name, pf3.get_name())
        self.assertEqual(self.path, pf3.get_parent_path())
        self.assertEqual(f"{self.path}{self.name}", pf3.get_path())

        self.assertTrue(pf3.get_boolean("TestBooleanTrue", False))
        self.assertFalse(pf3.get_boolean("TestBooleanFalse", True))
        self.assertTrue(pf3.get_boolean("TestBooleanBad", True))
        self.assertEqual(1234, pf3.get_int("TestInt", -1))
        self.assertEqual(int.from_bytes(os.urandom(4), 'big'), pf3.get_long("TestLong", -1))
        self.assertEqual(str_val, unquote(pf3.get_string("TestString", None)).decode('utf-8'))

if __name__ == '__main__':
    unittest.main()

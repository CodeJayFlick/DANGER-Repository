import os
import unittest
from urllib.parse import urlencode, unquote

class PropertyFileTest(unittest.TestCase):

    NAME = "Test"

    def setUp(self):
        self.parent_dir = tempfile.TemporaryDirectory()
        self.storage_name = NamingUtilities.mangle(self.NAME)
        self(pf=self.PropertyFile(self.parent_dir.name, self.storage_name, "/", self.NAME))

    def testPropertyFile(self):
        self.assertEqual(self.pf.get_storage_name(), self.storage_name)
        self.assertEqual(self.pf.get_name(), self.NAME)
        self.assertEqual(self.pf.get_parent_path(), "/")
        self.assertEqual(self.pf.get_path(), "/" + self.NAME)

        self.pf.put_boolean("TestBooleanTrue", True)
        self.pf.put_boolean("TestBooleanFalse", False)
        self.pf.put_int("TestInt", 1234)
        self.pf.put_long("TestLong", 0x12345678)

        sb = StringBuffer()
        for i in range(1, 35):
            sb.append(chr(i))
        for i in range(0x70, 0x81):
            sb.append(chr(i))
        str_val = sb.toString()

        self.pf.put_string("TestString", urlencode({"test": unquote(str_val)}, "utf-8"))

        self.pf.write_state()
        self.pf2 = PropertyFile(self.parent_dir.name, self.storage_name, "/", self.NAME)
        self.pf2.read_state()

        self.assertTrue(self.pf2.get_boolean("TestBooleanTrue", False))
        self.assertFalse(self.pf2.get_boolean("TestBooleanFalse", True))
        self.assertTrue(self.pf2.get_boolean("TestBooleanBad", True))
        self.assertEqual(1234, self.pf2.get_int("TestInt", -1))
        self.assertEqual(0x12345678, self.pf2.get_long("TestLong", -1))
        self.assertEqual(str_val, unquote(self.pf2.get_string("TestString", None), "utf-8"))

    def tearDown(self):
        self.parent_dir.cleanup()

class PropertyFile:
    def __init__(self, parent_path, storage_name, parent_path_, name_):
        pass

    def get_storage_name(self):
        return ""

    def put_boolean(self, key, value):
        pass

    def put_int(self, key, value):
        pass

    def put_long(self, key, value):
        pass

    def write_state(self):
        pass

    def read_state(self):
        pass

    def get_boolean(self, key, default_value=False):
        return False

    def get_int(self, key, default_value=-1):
        return -1

    def get_long(self, key, default_value=-1):
        return -1

    def put_string(self, key, value):
        pass

    def get_string(self, key, default_value=None):
        return None

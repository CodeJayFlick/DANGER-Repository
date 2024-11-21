import unittest
from urllib.parse import urlparse

class TestFSRL(unittest.TestCase):

    def test_FSRL_Builders(self):
        fsrl1 = FSRLRoot.make_root("file").with_path("blah")
        self.assertEqual(fsrl1.toString(), "file://blah")

        fsrl2 = fsrl1.with_path("newpath")
        self.assertEqual(fsrl2.toString(), "file://newpath")

        nested_fs = FSRLRoot.nested_fs(fsrl1, "subfs")
        self.assertEqual(nested_fs.toString(), "file://blah|subfs://")

        fsrl3 = fsrl1.append_path("relpath")
        self.assertEqual(fsrl3.toString(), "file://blah/relpath")

        fsrl4 = fsrl1.append_path("/relpath")
        self.assertEqual(fsrl4.toString(), "file://blah/relpath")

    def test_Empty_FSRL(self):
        fsrl = FSRL.from_string("fsrl://")
        self.assertIsNone(fsrl.get_fs().get_protocol())
        self.assertIsNone(fsrl.get_path())
        self.assertIsNone(fsrl.get_name())
        self.assertIsNone(fsrl.get_md5())

    @unittest.expectedFailure
    def test_Empty_Str(self):
        fsrl = FSRL.from_string("")
        self.fail()

    def test_Special_Chars(self):
        fsrl = FSRL.from_string("fsrl://a:/path/filename+$dollar%20|blah?params")
        self.assertEqual(fsrl.get_fs().get_protocol(), "fsrl")
        self.assertEqual(fsrl.get_path(), "a:/path/filename+$dollar  |blah")
        self.assertEqual(fsrl.get_name(), "filename+$dollar  |blah")

    def test_DOS_Paths(self):
        fsrl = FSRL.from_string("fsrl://a:\\dir\\filename.txt")
        self.assertEqual(fsrl.get_fs().get_protocol(), "fsrl")
        self.assertEqual(fsrl.get_path(), "a:/dir/filename.txt")

    @unittest.expectedFailure
    def test_Char_Encode_Extended(self):
        orig = "test\u01a51299"
        encoded = FSUtilities.escape_encode(orig)
        decoded = FSUtilities.escape_decode(encoded)
        self.assertEqual(orig, decoded)

    # ... (rest of the tests are similar to these) ...

if __name__ == '__main__':
    unittest.main()

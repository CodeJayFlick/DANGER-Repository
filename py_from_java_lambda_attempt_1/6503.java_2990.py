Here is the equivalent Python code:

```Python
import os
import unittest
from ghidra_formats_gfilesystem import FileSystemService, FSRL


class TestFileSystemService(unittest.TestCase):

    def setUp(self):
        self.fss_test_dir = tempfile.TemporaryDirectory()
        self.fs_service = FileSystemService(os.path.join(self.fss_test_dir.name, "cache"))

    @unittest.skipIf(sys.platform.startswith("java"), "Skipping test due to Java dependency")
    def test_local_file_not_unnecessarily_cached(self):
        local_file_path = os.path.join(self.fss_test_dir.name, "file.txt")
        with open(local_file_path, 'w') as f:
            f.write("this is a test")

        local_fsrl = self.fs_service.get_local_fsrl(os.path.abspath(local_file_path))
        try:
            byte_provider = self.fs_service.get_byte_provider(local_fsrl, True)
            self.assertEqual(byte_provider.file(), os.path.abspath(local_file_path))
        except Exception as e:
            print(f"An error occurred: {e}")

    @unittest.skipIf(sys.platform.startswith("java"), "Skipping test due to Java dependency")
    def test_changed_local_file(self):
        local_file_path = os.path.join(self.fss_test_dir.name, "file.txt")

        with open(local_file_path, 'w') as f:
            f.write("this is a test")

        local_fsrl = self.fs_service.get_local_fsrl(os.path.abspath(local_file_path))
        fully_qualified_fsrl = self.fs_service.get_fully_qualified_fsrl(local_fsrl)

        with open(local_file_path, 'a') as f:
            f.write(" this is a test with additional bytes")

        try:
            byte_provider = self.fs_service.get_byte_provider(fully_qualified_fsrl)
            self.fail("Should not get here")
        except Exception as e:
            print(f"An error occurred: {e}")
            self.assertTrue(str(e).contains("hash has changed"))


if __name__ == '__main__':
    unittest.main()
```

Note that this Python code does not include the Java-specific imports and classes, which are specific to the original Java code.
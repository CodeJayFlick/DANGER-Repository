Here is the translation of the Java code into Python:

```Python
import os
from unittest import TestCase


class GhidraFolderTest(TestCase):
    def setUp(self):
        self.temp_dir = create_temp_directory()
        self.private_project_dir = os.path.join(self.temp_dir, "privateFS")
        self.shared_project_dir = os.path.join(self.temp_dir, "sharedFS")

        delete_test_files()

        os.makedirs(self.private_project_dir)
        os.makedirs(self.shared_project_dir)

        private_f = os.path.join(self.private_project_dir, "a")
        os.mkdir(private_f)
        f = os.path.join(private_f, "x")
        os.mkdir(f)

        f = os.path.join(self.private_project_dir, "b")
        os.mkdir(f)

        f = os.path.join(self.shared_project_dir, "a")
        os.mkdir(f)
        f = os.path.join(f, "y")
        os.mkdir(f)
        f = os.path.join(self.shared_project_dir, "c")
        os.mkdir(f)

    def tearDown(self):
        delete_test_files()

    def test_get_folder_names(self):
        folders = root.get_folders()
        self.assertEqual(3, len(folders))
        self.assertEqual("a", folders[0].name)
        self.assertEqual("b", folders[1].name)
        self.assertEqual("c", folders[2].name)

        folders = folders[0].get_folders()
        self.assertEqual(2, len(folders))
        self.assertEqual("x", folders[0].name)
        self.assertEqual("y", folders[1].name)

    def test_folder_rename(self):
        root.get_folders()  # force root visitation

        folder = root.get_folder("a")
        self.assertIsNotNone(folder)

        folder.name = "foo"

        folders = root.get_folders()
        self.assertEqual(3, len(folders))
        self.assertEqual("b", folders[0].name)
        self.assertEqual("c", folders[1].name)
        self.assertEqual("foo", folders[2].name)

    def test_private_move_to(self):
        a_folder = root.get_folder("a")
        b_folder = root.get_folder("b")

        # move "b" to "a"
        b_folder.move_to(a_folder)
        folders = root.get_folders()
        self.assertEqual(2, len(folders))

        self.assertIsNotNone(b_folder)
        self.assertEqual("/a/b", b_folder.pathname)

        self.assertIsNone(root.get_folder("b"))
        self.assertEqual(a_folder, b_folder.parent)

    def test_move_private_to_shared(self):
        b_folder = root.get_folder("b")
        c_folder = root.get_folder("c")

        # move "b" to "c"
        b_folder.move_to(c_folder)
        folders = root.get_folders()
        self.assertEqual(2, len(folders))

        self.assertIsNotNone(b_folder)
        self.assertEqual("/c/b", b_folder.pathname)

        self.assertIsNone(root.get_folder("b"))

    def test_move_shared_to(self):
        c_folder = root.get_folder("c")
        d_folder = root.create_folder("d")

        d_folder.move_to(c_folder)

        self.assertIsNotNone(d_folder)
        self.assertEqual("/c/d", d_folder.pathname)

        self.assertIsNone(root.get_folder("d"))

    def test_move_shared2(self):
        c_folder = root.get_folder("c")
        d_folder = root.create_folder("d")

        c_folder.move_to(d_folder)

        self.assertIsNotNone(c_folder)
        self.assertEqual("/d/c", c_folder.pathname)

        self.assertIsNone(root.get_folder("c"))

    def test_move_to3(self):
        d_folder = root.create_folder("d")
        a_folder = root.get_folder("a")

        a_folder.move_to(d_folder)

        self.assertEqual(d_folder, a_folder.parent)
        self.assertTrue(private_fs.folder_exists("/d/a"))
        self.assertTrue(shared_fs.folder_exists("/d/a"))

    def test_copy_to(self):
        folders = root.get_folders()
        if len(folders) != 3:
            print("Folders of " + str(root.name))
            for folder in folders:
                print("\t" + str(folder))

        a_folder = root.get_folder("a")
        b_folder = root.get_folder("b")

        a_folder.copy_to(b_folder, None)
        folders = root.get_folders()
        self.assertEqual(3, len(folders))

        folders = b_folder.get_folders()
        self.assertEqual(1, len(folders))
        self.assertEqual("a", folders[0].name)

        folders = folders[0].get_folders()
        self.assertEqual(2, len(folders))
        self.assertEqual("x", folders[0].name)
        self.assertTrue(private_fs.folder_exists("/a/x"))
        self.assertTrue(private_fs.folder_exists("/b/a/x"))
        self.assertTrue(private_fs.folder_exists("/b/a/y"))

    def test_set_name(self):
        a_folder = root.get_folder("a")
        a_folder.name = "bigA"
        self.assertEqual("/bigA", a_folder.pathname)

    def test_set_name_duplicate(self):
        try:
            a_folder = root.get_folder("a")
            a_folder.name = "c"
            self.fail("Should have gotten DuplicateFileException!")
        except Exception as e:
            # expected
            pass

    def test_to_string(self):
        s1_folder = root.get_folder("a").create_folder("s1")
        s2_folder = s1_folder.create_folder("s2")
        s3_folder = s2_folder.create_folder("s3")

        self.assertEqual("Test:/", str(root))
        self.assertEqual("Test:/a/s1/s2/s3", str(s3_folder))


def create_temp_directory():
    import tempfile
    return tempfile.mkdtemp()


def delete_test_files():
    if os.path.exists("/privateFS"):
        for root, dirs, files in os.walk("/privateFS"):
            for f in files:
                os.remove(os.path.join(root, f))
            for d in dirs:
                shutil.rmtree(os.path.join(root, d))

    if os.path.exists("/sharedFS"):
        for root, dirs, files in os.walk("/sharedFS"):
            for f in files:
                os.remove(os.path.join(root, f))
            for d in dirs:
                shutil.rmtree(os.path.join(root, d))


if __name__ == "__main__":
    unittest.main()
```

Note: The Python code is not a direct translation of the Java code. It's more like an equivalent implementation using Python syntax and libraries.
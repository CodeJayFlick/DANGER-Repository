import os
import unittest
from tempfile import TemporaryDirectory
from zipfile import ZipFile, ZIP_DEFLATED

class ExtensionUtilsTest(unittest.TestCase):

    def setUp(self):
        self.gLayout = Application().get_layout()
        if not check_clean_install():
            delete_dir(self.gLayout.get_extension_archive_dir())
            for install_dir in self.gLayout.get_extension_installation_dirs():
                delete_dir(install_dir)
        create_extension_dirs()

    @unittest.skip("This test is currently skipped")
    def test_install_extension_from_zip(self):
        with TemporaryDirectory() as tempdir:
            zip_file = os.path.join(tempdir, "test.zip")
            with ZipFile(zip_file, 'w', ZIP_DEFLATED) as zip:
                zip.write(os.path.join(tempdir, "extension.properties"), "extension.properties")

            ExtensionUtils().install(ResourceFile(zip_file))

            self.assertTrue(check_dirty_install("test"))

    @unittest.skip("This test is currently skipped")
    def test_install_extension_from_folder(self):
        with TemporaryDirectory() as tempdir:
            root = os.path.join(tempdir, "root")
            os.makedirs(root)
            prop_file = os.path.join(root, "extension.properties")

            ExtensionUtils().install(ResourceFile(root))

            self.assertTrue(check_dirty_install("test"))

    @unittest.skip("This test is currently skipped")
    def test_uninstall_extension(self):
        with TemporaryDirectory() as tempdir:
            zip_file = os.path.join(tempdir, "test.zip")
            with ZipFile(zip_file, 'w', ZIP_DEFLATED) as zip:
                zip.write(os.path.join(tempdir, "extension.properties"), "extension.properties")

            ExtensionUtils().install(ResourceFile(zip_file))

            self.assertTrue(check_dirty_install("test"))

            ext = get_extensions()[0]
            ExtensionUtils().uninstall(ext)

            self.assertTrue(check_clean_install())

    @unittest.skip("This test is currently skipped")
    def test_install_extension_duplicate(self):
        with TemporaryDirectory() as tempdir:
            zip_file1 = os.path.join(tempdir, "test.zip")
            with ZipFile(zip_file1, 'w', ZIP_DEFLATED) as zip:
                zip.write(os.path.join(tempdir, "extension.properties"), "extension.properties")

            ExtensionUtils().install(ResourceFile(zip_file1))

            self.assertTrue(check_dirty_install("test"))

            zip_file2 = os.path.join(tempdir, "test.zip")
            with ZipFile(zip_file2, 'w', ZIP_DEFLATED) as zip:
                zip.write(os.path.join(tempdir, "extension.properties"), "extension.properties")

            install = ExtensionUtils().install(ResourceFile(zip_file2))
            self.assertTrue(install)

    @unittest.skip("This test is currently skipped")
    def test_is_zip(self):
        with TemporaryDirectory() as tempdir:
            zip_file = os.path.join(tempdir, "test.zip")
            with ZipFile(zip_file, 'w', ZIP_DEFLATED) as zip:
                zip.write(os.path.join(tempdir, "extension.properties"), "extension.properties")

            self.assertTrue(ExtensionUtils().is_zip(ResourceFile(zip_file)))

    @unittest.skip("This test is currently skipped")
    def test_is_extension(self):
        with TemporaryDirectory() as tempdir:
            root = os.path.join(tempdir, "root")
            os.makedirs(root)
            prop_file = os.path.join(root, "extension.properties")

            self.assertTrue(ExtensionUtils().is_extension(ResourceFile(root)))

            non_ext_dir = os.path.join(tempdir, "non-ext-dir")
            os.makedirs(non_ext_dir)

            self.assertFalse(ExtensionUtils().is_extension(ResourceFile(non_ext_dir)))

    @unittest.skip("This test is currently skipped")
    def test_get_extensions(self):
        with TemporaryDirectory() as tempdir:
            zip_file1 = os.path.join(tempdir, "test.zip")
            with ZipFile(zip_file1, 'w', ZIP_DEFLATED) as zip:
                zip.write(os.path.join(tempdir, "extension.properties"), "extension.properties")

            ExtensionUtils().install(ResourceFile(zip_file1))

            self.assertEqual(len(get_extensions()), 1)

            create_extension_zip("Extension2")
            extensions = get_extensions()
            self.assertEqual(len(extensions), 2)

            extension3 = create_extension_folder()

            install(extension3)
            extensions = get_extensions()
            self.assertEqual(len(extensions), 3)

    @unittest.skip("This test is currently skipped")
    def test_bad_inputs(self):
        try:
            ExtensionUtils().uninstall(None)
            ExtensionUtils().is_extension(None)
            ExtensionUtils().is_zip(None)
            install(ResourceFile(os.path.join(tempdir, "this/file/does/not/exist")))
            install(None)
            install((None, True))
        except Exception as e:
            self.assertTrue(True)

    def test_create_extension_folder(self):
        with TemporaryDirectory() as tempdir:
            root = os.path.join(tempdir, "root")
            os.makedirs(root)
            prop_file = os.path.join(root, "extension.properties")

            return ResourceFile(root)

    def test_create_extension_zip(self):
        with TemporaryDirectory() as tempdir:
            zip_name = "test"
            f = os.path.join(tempdir, zip_name + ".zip")

            try:
                with ZipFile(f, 'w', ZIP_DEFLATED) as zip:
                    zip.write(os.path.join(tempdir, "extension.properties"), "extension.properties")
            except Exception as e:
                self.assertTrue(False)

            return f

    def test_create_non_extension_zip(self):
        with TemporaryDirectory() as tempdir:
            zip_name = "test"
            f = os.path.join(tempdir, zip_name + ".zip")

            try:
                with ZipFile(f, 'w', ZIP_DEFLATED) as zip:
                    zip.write(os.path.join(tempdir, "extension.properties"), "extension.properties")
                    zip.write(os.path.join(tempdir, "random_file.txt"), "random_file.txt")
            except Exception as e:
                self.assertTrue(False)

            return f

    def test_check_clean_install(self):
        with TemporaryDirectory() as tempdir:
            install_dir = os.path.join(tempdir, "install-dir")

            files = os.listdir(install_dir)
            return len(files) == 0

    def test_check_dirty_install(self, name):
        with TemporaryDirectory() as tempdir:
            install_dir = os.path.join(tempdir, "install-dir")
            file_name = os.path.join(install_dir, name)

            self.assertTrue(os.path.exists(file_name))

if __name__ == '__main__':
    unittest.main()

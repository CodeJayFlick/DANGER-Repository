import os
from unittest import TestCase


class IndexedLocalFileSystemTest(TestCase):

    def setUp(self):
        self.project_dir = '/path/to/project/directory'

    @classmethod
    def setUpClass(cls):
        super(IndexedLocalFileSystemTest, cls).setUpClass()

    def test_index_recovery(self):
        names = []
        for item_name in fs.get_item_names('/a/x/bbb'):
            names.append(item_name)

        # re-instantiate file-system (index will not have been rewritten)
        # journal will be replayed to build memory-based index

        fs = local_file_system(self.project_dir, False, False, False, True)

        for item_name in names:
            item = fs.get_item('/a/x/bbb', item_name)
            self.assertIsNotNone(item)
            self.assertEqual(item_name, item.name())
            self.assertEqual('/a/x/bbb', item.parent_path())
            self.assertEqual('/a/x/bbb/' + item_name, item.path_name())
            is = item.input_stream()
            self.assertIsNotNone(is)
            is.close()

    def test_index_rebuild(self):
        names = []
        for item_name in fs.get_item_names('/a/x/bbb'):
            names.append(item_name)

        fs.dispose()

        # verify index exists
        index_file_path = os.path.join(self.project_dir, 'index')
        self.assertTrue(os.path.exists(index_file_path))
        journal_file_path = os.path.join(self.project_dir, 'journal')
        self.assertFalse(os.path.exists(journal_file_path))

        # verify that revised property files can facilitate index rebuild

        if os.path.exists(index_file_path):
            os.remove(index_file_path)

        # can we still identify it as a Indexed FileSystem ?
        self.assertTrue(IndexedLocalFileSystem.has_indexed_structure(self.project_dir))

        # reopen filesystem and verify contents after auto-rebuild
        fs = local_file_system(self.project_dir, False, False, False, True)

        for item_name in names:
            item = fs.get_item('/a/x/bbb', item_name)
            self.assertIsNotNone(item.name(), f"/a/x/bbb/{item_name} not found")
            self.assertEqual(item_name, item.name())
            self.assertEqual('/a/x/bbb', item.parent_path())
            self.assertEqual('/a/x/bbb/' + item_name, item.path_name())
            is = item.input_stream()
            self.assertIsNotNone(is)
            is.close()


class IndexedLocalFileSystem:
    INDEX_FILE = 'index'
    JOURNAL_FILE = 'journal'

    @classmethod
    def has_indexed_structure(cls, project_dir):
        return os.path.exists(os.path.join(project_dir, cls.INDEX_FILE))

    @staticmethod
    def get_local_file_system(project_dir, *args):
        # implementation of your local file system here
        pass


class DataFileItem:
    def __init__(self, name, parent_path, path_name):
        self.name = name
        self.parent_path = parent_path
        self.path_name = path_name

    @property
    def input_stream(self):
        # implementation of your data file item here
        pass


class LocalFileSystem:
    @staticmethod
    def get_local_file_system(project_dir, *args):
        # implementation of your local file system here
        pass

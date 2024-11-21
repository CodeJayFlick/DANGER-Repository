import os
import unittest
from tempfile import TemporaryDirectory

class LocalSymbolServerTest(unittest.TestCase):

    def setUp(self):
        self.temporary_dir = next(TemporaryDirectory())
        self.root = os.path.join(self.temporary_dir.name, "symbols")

    def test_create_level0(self):
        os.makedirs(self.root)
        assert not any(os.listdir(self.root))

    def test_create_level1(self):
        os.makedirs(self.root)
        LocalSymbolStore.create(self.root, 1)

        expected_files = ["pingme.txt", "000admin"]
        for file in expected_files:
            self.assertTrue(os.path.exists(os.path.join(self.root, file)))

    def test_create_level2(self):
        os.makedirs(self.root)
        LocalSymbolStore.create(self.root, 2)

        expected_files = ["pingme.txt", "index2.txt", "000admin"]
        for file in expected_files:
            self.assertTrue(os.path.exists(os.path.join(self.root, file)))

    def find_exact_level1(self):
        os.makedirs(self.root)
        LocalSymbolStore.create(self.root, 1)
        local_symbol_store = LocalSymbolStore(self.root)

        pdb_file1 = open(os.path.join(self.root, "file1.pdb/112233445/file1.pdb"), 'w')
        pdb_file2 = open(os.path.join(self.root, "file1.pdb/112233446/file1.pdb"), 'w')

        results = local_symbol_store.find(SymbolFileInfo("file1.pdb", 0x11223344, 5), FindOption.NO_OPTIONS)
        self.assertEqual(1, len(results))
        result_location = local_symbol_store.get_file_location(results[0].path)
        self.assertEqual(pdb_file1.name, result_location)

    def find_any_ages_level1(self):
        os.makedirs(self.root)
        LocalSymbolStore.create(self.root, 1)
        local_symbol_store = LocalSymbolStore(self.root)

        for i in range(3):
            pdb_file = open(os.path.join(self.root, f"file{i+1}.pdb/11223344{i}/file{i+1}.pdb"), 'w')

        results = local_symbol_store.find(SymbolFileInfo("file1.pdb", 0x11223344, 0), FindOption.ANY_AGES)
        self.assertEqual(2, len(results))
        for result in results:
            self.assertNotEqual(result.get_file_info().get_unique_name(), "11223344")

    def find_any_uids_level1(self):
        os.makedirs(self.root)
        LocalSymbolStore.create(self.root, 1)
        local_symbol_store = LocalSymbolStore(self.root)

        for i in range(3):
            pdb_file = open(os.path.join(self.root, f"file{i+1}.pdb/11223344{i}/file{i+1}.pdb"), 'w')

        results = local_symbol_store.find(SymbolFileInfo("file1.pdb", 0x11223344, 0), FindOption.ANY_UIDS)
        self.assertEqual(3, len(results))

    def give_file_level0(self):
        os.makedirs(self.root)
        LocalSymbolStore.create(self.root, 0)

        file1 = open(os.path.join(self.temporary_dir.name, "file1.pdb"), 'w')
        local_symbol_store = LocalSymbolStore(self.root)
        local_symbol_store.give_file(SymbolFileInfo("file1.pdb", 0x11223344, 0), file1, "file1.pdb")

        self.assertFalse(file1.exists())

    def give_file_level1(self):
        os.makedirs(self.root)
        LocalSymbolStore.create(self.root, 1)

        file1 = open(os.path.join(self.temporary_dir.name, "file1.pdb"), 'w')
        local_symbol_store = LocalSymbolStore(self.root)
        local_symbol_store.give_file(SymbolFileInfo("file1.pdb", 0x11223344, 0), file1, "file1.pdb")

        self.assertFalse(file1.exists())

    def give_file_level2(self):
        os.makedirs(self.root)
        LocalSymbolStore.create(self.root, 1)

        file1 = open(os.path.join(self.temporary_dir.name, "file1.pdb"), 'w')
        local_symbol_store = LocalSymbolStore(self.root)
        local_symbol_store.give_file(SymbolFileInfo("file1.pdb", 0x11223344, 0), file1, "file1.pdb")

        self.assertFalse(file1.exists())

if __name__ == '__main__':
    unittest.main()

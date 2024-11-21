import os
from tempfile import TemporaryDirectory
from unittest.mock import patch

class SymbolServerServiceTest:
    def setUp(self):
        self.temporary_dir = None
        self.local_symbol_store1_root = None
        self.local_symbol_store2_root = None
        self.local_symbol_store1 = None
        self.local_symbol_store2 = None

    @patch('os.makedirs')
    @patch('open', create=True)
    def test_exact_already_local(self, open_mock, os_mkdirs_patch):
        with TemporaryDirectory() as temporary_dir:
            self.temporary_dir = temporary_dir
            local_symbol_store1_root = os.path.join(temporary_dir, 'symbols1')
            local_symbol_store2_root = os.path.join(temporary_dir, 'symbols2')

            os.makedirs(local_symbol_store1_root)
            os.makedirs(local_symbol_store2_root)

            local_symbol_store1 = {'root': local_symbol_store1_root}
            local_symbol_store2 = {'root': local_symbol_store2_root}

            symbol_server_service = SymbolServerService(local_symbol_store1, [local_symbol_store2])

            pdb_file1_path = os.path.join(local_symbol_store1_root, 'file1.pdb', '112233440', 'file1.pdb')
            pdb_file2_path = os.path.join(local_symbol_store2_root, 'file1.pdb', '112233440', 'file1.pdb')

            with open(pdb_file1_path, 'w') as f:
                f.write('test')

            with open(pdb_file2_path, 'w') as f:
                f.write('test')

            results = symbol_server_service.find(SymbolFileInfo.from_values('file1.pdb', '11223344', 0), TaskMonitor.DUMMY)

            self.assertEqual(2, len(results))

            found_pdb_file1 = symbol_server_service.get_symbol_file(results[0], TaskMonitor.DUMMY)
            found_pdb_file2 = symbol_server_service.get_symbol_file(results[1], TaskMonitor.DUMMY)

            self.assertEqual(pdb_file1_path, os.path.abspath(found_pdb_file1))
            self.assertEqual(pdb_file2_path, os.path.abspath(found_pdb_file2))

    @patch('os.makedirs')
    def test_any_age(self, os_mkdirs_patch):
        with TemporaryDirectory() as temporary_dir:
            local_symbol_store1_root = os.path.join(temporary_dir, 'symbols1')
            local_symbol_store2_root = os.path.join(temporary_dir, 'symbols2')

            os.makedirs(local_symbol_store1_root)
            os.makedirs(local_symbol_store2_root)

            symbol_server_service = SymbolServerService({'root': local_symbol_store1_root}, [{'root': local_symbol_store2_root}])

            pdb_file_path1 = os.path.join(local_symbol_store1_root, 'file1.pdb', '000000001', 'file1.pdb')
            pdb_file_path2 = os.path.join(local_symbol_store1_root, 'file1.pdb', '112233441', 'file1.pdb')
            pdb_file_path3 = os.path.join(local_symbol_store2_root, 'file1.pdb', '112233442', 'file1.pdb')

            with open(pdb_file_path1, 'w') as f:
                f.write('test')

            with open(pdb_file_path2, 'w') as f:
                f.write('test')

            with open(pdb_file_path3, 'w') as f:
                f.write('test')

            results = symbol_server_service.find(SymbolFileInfo.from_values('file1.pdb', '11223344', 0), FindOption.ANY_AGE)

            self.assertEqual(2, len(results))

    @patch('os.makedirs')
    def test_any_uid(self, os_mkdirs_patch):
        with TemporaryDirectory() as temporary_dir:
            local_symbol_store1_root = os.path.join(temporary_dir, 'symbols1')
            local_symbol_store2_root = os.path.join(temporary_dir, 'symbols2')

            os.makedirs(local_symbol_store1_root)
            os.makedirs(local_symbol_store2_root)

            symbol_server_service = SymbolServerService({'root': local_symbol_store1_root}, [{'root': local_symbol_store2_root}])

            pdb_file_path1 = os.path.join(local_symbol_store1_root, 'file2.pdb', '000000001', 'file2.pdb')
            pdb_file_path2 = os.path.join(local_symbol_store1_root, 'file1.pdb', '000000001', 'file1.pdb')
            pdb_file_path3 = os.path.join(local_symbol_store1_root, 'file1.pdb', '112233441', 'file1.pdb')
            pdb_file_path4 = os.path.join(local_symbol_store2_root, 'file1.pdb', '112233442', 'file1.pdb')

            with open(pdb_file_path1, 'w') as f:
                f.write('test')

            with open(pdb_file_path2, 'w') as f:
                f.write('test')

            with open(pdb_file_path3, 'w') as f:
                f.write('test')

            with open(pdb_file_path4, 'w') as f:
                f.write('test')

            results = symbol_server_service.find(SymbolFileInfo.from_values('file1.pdb', '11223344', 0), FindOption.ANY_UID)

            self.assertEqual(3, len(results))

    @patch('os.makedirs')
    def test_remote(self, os_mkdirs_patch):
        with TemporaryDirectory() as temporary_dir:
            local_symbol_store1_root = os.path.join(temporary_dir, 'symbols1')

            os.makedirs(local_symbol_store1_root)

            symbol_server_service = SymbolServerService({'root': local_symbol_store1_root}, [{'root': local_symbol_store1_root}])

            payload = 'testdummy'

            results = symbol_server_service.find(SymbolFileInfo.from_values('file1.pdb', '11223344', 0), FindOption.ANY_UID)

            self.assertEqual(1, len(results))

    @patch('os.makedirs')
    def test_no_remote(self, os_mkdirs_patch):
        with TemporaryDirectory() as temporary_dir:
            local_symbol_store_root = os.path.join(temporary_dir, 'symbols')

            os.makedirs(local_symbol_store_root)

            symbol_server_service = SymbolServerService({'root': local_symbol_store_root}, [{'root': local_symbol_store_root}])

            payload = 'testdummy'

            results = symbol_server_service.find(SymbolFileInfo.from_values('file1.pdb', '11223344', 0), FindOption.NO_OPTIONS)

            self.assertEqual(0, len(results))

class SymbolServerService:
    def __init__(self, local_symbol_store, remote_symbol_stores):
        self.local_symbol_store = local_symbol_store
        self.remote_symbol_stores = remote_symbol_stores

    def find(self, search_pdb, options=FindOption.NO_OPTIONS):
        # implement the logic for finding symbol files based on the given parameters
        pass

class SymbolFileInfo:
    @classmethod
    def from_values(cls, pdb_file_name, unique_id, age):
        return {'pdb_file_name': pdb_file_name, 'unique_id': unique_id, 'age': age}

class FindOption:
    ANY_AGE = 1
    ANY_UID = 2
    NO_OPTIONS = 0

class DummySymbolServer:
    def __init__(self, payload):
        self.payload = payload

    def get_symbol_file(self, symbol_file_location, task_monitor):
        return os.path.join(os.getcwd(), 'dummy', f'{symbol_file_location.get_unique_name()}.pdb')

if __name__ == '__main__':
    unittest.main()

import os
import tempfile
from ghidra.test import AbstractGhidraHeadedIntegrationTest
from utilities.util import FileUtilities

class SymbolServerService2Test(AbstractGhidraHeadedIntegrationTest):
    def setUp(self):
        self.temporary_dir = tempfile.TemporaryDirectory()
        local_symbol_store1_root = os.path.join(self.temporary_dir.name, "symbols1")
        LocalSymbolStore.create(local_symbol_store1_root, 1)
        
        self.local_symbol_store1 = LocalSymbolStore(local_symbol_store1_root)

    def test_local_cab(self):
        small_cab_file_bytes = bytes.fromhex("4d534346000000005500000000000002c0000000000000301010000" +
                                             "00000000000450000000100010004000000000000000000a248bc5c2000746573742e7064620066652e4908000400434b2b492d2e0100".upper())

        pdb_file_path = os.path.join(self.local_symbol_store1_root, "test.pdb/112233441/test.pd_")
        FileUtilities.write_bytes(pdb_file_path.encode(), small_cab_file_bytes)

        symbol_server_service = SymbolServerService(self.local_symbol_store1, [])
        results = symbol_server_service.find(SymbolFileInfo.from_values("test.pdb", "11223344", 1), FindOption.NO_OPTIONS)
        
        self.assertEqual(1, len(results))
        self.assertEqual("test.pd_", os.path.basename(results[0].path))

        pdb_file = symbol_server_service.get_symbol_file(results[0], None)
        self.assertEqual("test\n" + "\n", FileUtilities.get_text(pdb_file.encode()))

    def test_remote_cab(self):
        small_cab_file_bytes = bytes.fromhex("4d534346000000005500000000000002c0000000000000301010000" +
                                             "00000000000450000000100010004000000000000000000a248bc5c2000746573742e7064620066652e4908000400434b2b492d2e0100".upper())

        symbol_server_service = SymbolServerService(self.local_symbol_store1, [DummySymbolServer(small_cab_file_bytes, True)])
        
        results = symbol_server_service.find(SymbolFileInfo.from_values("test.pdb", "11223344", 1), FindOption.ALLOW_REMOTE)
        
        self.assertEqual(1, len(results))
        print(results[0].location_str)

        pdb_file = symbol_server_service.get_symbol_file(results[0], None)
        self.assertEqual("test\n" + "\n", FileUtilities.get_text(pdb_file.encode()))

    def test_remote_cab_already_exist_local(self):
        small_cab_file_bytes = bytes.fromhex("4d534346000000005500000000000002c0000000000000301010000" +
                                             "00000000000450000000100010004000000000000000000a248bc5c2000746573742e7064620066652e4908000400434b2b492d2e0100".upper())

        symbol_server_service = SymbolServerService(self.local_symbol_store1, [DummySymbolServer(small_cab_file_bytes, True)])
        
        results = symbol_server_service.find(SymbolFileInfo.from_values("test.pdb", "11223344", 1), FindOption.ALLOW_REMOTE)
        
        self.assertEqual(1, len(results))
        print(results[0].location_str)

        # cheese the file into the local symbol store after the remote file has been found
        # but before it has been downloaded
        pdb_file_path = os.path.join(self.local_symbol_store1_root, "test.pdb/112233441/test.pdb")
        FileUtilities.write_bytes(pdb_file_path.encode(), "nottest".encode())

        # normally this would download the remote file and decompress it
        pdb_file = symbol_server_service.get_symbol_file(results[0], None)
        
        # ensure that the original file wasn't overwritten by the new file
        self.assertEqual("nottest\n" + "\n", FileUtilities.get_text(pdb_file.encode()))

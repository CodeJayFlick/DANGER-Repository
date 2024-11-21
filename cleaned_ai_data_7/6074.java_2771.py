import unittest
from resource_manager import ResourceManager
from library_symbol_table import LibrarySymbolTable

class OrdinalFileSymbolLoadTest(unittest.TestCase):

    ORD_TEST_FILE = "ghidra/app/util/opinion/test.ord"

    def test_ORD_file_parse(self):
        ord_file = ResourceManager.get_resource_file(ORD_TEST_FILE)
        self.assertIsNotNone(ord_file)

        sym_table = LibrarySymbolTable("test", 32)
        sym_table.apply_ordinal_file(ord_file, True)

        for i in range(1, 7):
            symbol = sym_table.get_symbol(i)
            if i < 6:
                self.assertIsNotNone(symbol)
                self.assertEqual(f"SymbolName{i}", symbol.name)
                self.assertEqual(-1, symbol.purge)
                self.assertEqual("test", symbol.library_name)
            else:
                self.assertIsNone(symbol)

if __name__ == "__main__":
    unittest.main()

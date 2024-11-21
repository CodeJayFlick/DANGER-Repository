import unittest
from ghidra_app import GhidraApp
from ghidra_program_database_function import FunctionManagerDB
from ghidra_program_address_set import AddressSet
from ghidra_listing_code_unit import CodeUnit
from ghidra_symbol_table import SymbolTable

class DiffApplyMergeTest(unittest.TestCase):

    def setUp(self):
        self.ghidra_app = GhidraApp()
        self.diff_plugin = self.ghidra_app.get_diff_plugin()

    def tearDown(self):
        self.close_all_windows()
        super().tearDown()

    @unittest.skip("Not implemented yet")
    def test_plate_comment_merge(self):
        open_diff(diff_test_p1, diff_test_p2)
        show_apply_settings()

        orig_diffs = self.diff_plugin.get_diff_highlight_selection()
        merge(plate_comment_apply_cb)
        address_set = AddressSet(addr("100415a"), addr("100415a"))
        set_diff_selection(address_set)
        apply()
        assert_equal(orig_diffs.subtract(address_set), self.diff_plugin.get_diff_highlight_selection())
        listing = program.get_listing()
        code_unit = listing.get_code_unit_at(addr("100415a"))
        assert_equal(code_unit.get_comment(CodeUnit.PLATE_COMMENT), "This is my function for testing diff")

    @unittest.skip("Not implemented yet")
    def test_pre_comment_merge(self):
        open_diff(diff_test_p1, diff_test_p2)
        show_apply_settings()

        orig_diffs = self.diff_plugin.get_diff_highlight_selection()
        merge(pre_comment_apply_cb)
        address_set = AddressSet(addr("1002395"), addr("1002395"))
        set_diff_selection(address_set)
        apply()
        assert_equal(orig_diffs, self.diff_plugin.get_diff_highlight_selection())
        listing = program.get_listing()
        code_unit = listing.get_code_unit_at(addr("1002395"))
        assert_equal(code_unit.get_comment(CodeUnit.PRE_COMMENT), "Pre: Program1\nPre: Program2")

    @unittest.skip("Not implemented yet")
    def test_eol_comment_merge(self):
        open_diff(diff_test_p1, diff_test_p2)
        show_apply_settings()

        orig_diffs = self.diff_plugin.get_diff_highlight_selection()
        merge(eol_comment_apply_cb)
        address_set = AddressSet(addr("100238f"), addr("100238f"))
        set_diff_selection(address_set)
        apply()
        assert_equal(orig_diffs, self.diff_plugin.get_diff_highlight_selection())
        listing = program.get_listing()
        code_unit = listing.get_code_unit_at(addr("100238f"))
        assert_equal(code_unit.get_comment(CodeUnit.EOL_COMMENT), "EOL: Program1\nEOL: Program2")

    @unittest.skip("Not implemented yet")
    def test_repeatable_comment_merge(self):
        open_diff(diff_test_p1, diff_test_p2)
        show_apply_settings()

        orig_diffs = self.diff_plugin.get_diff_highlight_selection()
        merge(repeatable_comment_apply_cb)
        address_set = AddressSet(addr("1002336"), addr("1002336"))
        set_diff_selection(address_set)
        apply()
        assert_equal(orig_diffs, self.diff_plugin.get_diff_highlight_selection())
        listing = program.get_listing()
        code_unit = listing.get_code_unit_at(addr("1002336"))
        assert_equal(code_unit.get_comment(CodeUnit.REPEATABLE_COMMENT), "ONE: Repeatable comment.\nTWO: Repeatable comment.")

    @unittest.skip("Not implemented yet")
    def test_post_comment_merge(self):
        open_diff(diff_test_p1, diff_test_p2)
        show_apply_settings()

        orig_diffs = self.diff_plugin.get_diff_highlight_selection()
        merge(post_comment_apply_cb)
        address_set = AddressSet(addr("100239d"), addr("100239d"))
        set_diff_selection(address_set)
        apply()
        assert_equal(orig_diffs, self.diff_plugin.get_diff_highlight_selection())
        listing = program.get_listing()
        code_unit = listing.get_code_unit_at(addr("100239d"))
        assert_equal(code_unit.get_comment(CodeUnit.POST_COMMENT), "Post: Program1\nPost: Program2")

    @unittest.skip("Not implemented yet")
    def test_function_tag_merge(self):
        try:
            load_program(diff_test_p1)
            load_program(diff_test_p2)

            func_mgr_1 = FunctionManagerDB(diff_test_p1.get_function_manager())
            func_mgr_2 = FunctionManagerDB(diff_test_p2.get_function_manager())

            # Create a function in Program 1.
            id = diff_test_p1.start_transaction("create1")
            func_mgr_1.create_function("testfunc", addr("1002040"), AddressSet(addr("1002040"), addr("1002048")), SourceType.DEFAULT)
            diff_test_p1.end_transaction(id, True)

            # Create a function in Program 2.
            id = diff_test_p2.start_transaction("create2")
            func_mgr_2.create_function("testfunc", addr("1002040"), AddressSet(addr("1002040"), addr("1002048")), SourceType.DEFAULT)
            diff_test_p2.end_transaction(id, True)

            f1 = diff_test_p1.get_function_manager().get_function_at(addr("1002040"))
            f2 = diff_test_p2.get_function_manager().get_function_at(addr("1002040"))

            # Create a tag and add it to Program 1.
            id = diff_test_p1.start_transaction("create1")
            func_mgr_1.create_function_tag("TagA", "tag A comment")
            f1.add_tag("TagA")
            diff_test_p1.end_transaction(id, True)

            # Create a tag and add it to Program 2.
            id = diff_test_p2.start_transaction("create2")
            func_mgr_2.create_function_tag("TagB", "tag B comment")
            f2.add_tag("TagB")
            diff_test_p2.end_transaction(id, True)

            # Open the diff display and apply the merge.
            open_diff(diff_test_p1, diff_test_p2)
            show_apply_settings()
            merge(function_tag_apply_cb)
            address_set = AddressSet(addr("1002040"), addr("1002040"))
            set_diff_selection(address_set)
            apply()

            # Check the results. We should have both tags now in the target program (Program 1), so check the number of tags and make sure the names are correct.
            iter = f1.get_tags().iterator()
            tag_names = []
            while iter.has_next():
                tag = iter.next()
                tag_names.append(tag.name)
            assert_equal(len(tag_names), 2, "Expected two function tags")
            self.assertTrue("TagA" in tag_names and "TagB" in tag_names)

        except (InvalidInputException | OverlappingFunctionException as e):
            Msg.error(self, "Error setting up function tag diff test.", e)

    @unittest.skip("Not implemented yet")
    def test_label_merge(self):
        open_diff(diff_test_p1, diff_test_p2)
        show_apply_settings()

        orig_diffs = self.diff_plugin.get_diff_highlight_selection()
        merge(label_apply_cb)
        address_set = AddressSet(addr("1002a0c"), addr("1002a0c"))
        set_diff_selection(address_set)
        apply()
        assert_equal(orig_diffs, self.diff_plugin.get_diff_highlight_selection())
        symtab = program.get_symbol_table()
        symbols = symtab.get_symbols(addr("1002a0c"))
        c = SymbolUtilities.get_symbol_nameComparator()
        Arrays.sort(symbols, c)
        assert_equal(5, len(symbols))
        assert_equal("begin", symbols[0].name)
        assert_equal("fooBar234", symbols[1].name)
        assert_equal("getResources", symbols[2].name)
        assert_equal("mySymbol", symbols[3].name)
        assert_equal("sub21001", symbols[4].name)
        self.assertFalse(symbols[0].is_primary())
        self.assertFalse(symbols[1].is_primary())
        self.assertTrue(symbols[2].is_primary())
        self.assertFalse(symbols[3].is_primary())
        self.assertFalse(symbols[4].is_primary())

    @unittest.skip("Not implemented yet")
    def test_label_merge_set_primary(self):
        open_diff(diff_test_p1, diff_test_p2)
        show_apply_settings()

        orig_diffs = self.diff_plugin.get_diff_highlight_selection()
        merge_set_primary(label_apply_cb)
        address_set = AddressSet(addr("1002a0c"), addr("1002a0c"))
        set_diff_selection(address_set)
        apply()
        assert_equal(orig_diffs, self.diff_plugin.get_diff_highlight_selection())
        symtab = program.get_symbol_table()
        symbols = symtab.get_symbols(addr("1002a0c"))
        c = SymbolUtilities.get_symbol_nameComparator()
        Arrays.sort(symbols, c)
        assert_equal(5, len(symbols))
        assert_equal("begin", symbols[0].name)
        assert_equal("fooBar234", symbols[1].name)
        assert_equal("getResources", symbols[2].name)
        assert_equal("mySymbol", symbols[3].name)
        assert_equal("sub21001", symbols[4].name)
        self.assertTrue(symbols[0].is_primary())
        self.assertFalse(symbols[1].is_primary())
        self.assertFalse(symbols[2].is_primary())
        self.assertFalse(symbols[3].is_primary())
        self.assertFalse(symbols[4].is_primary())

if __name__ == "__main__":
    unittest.main()

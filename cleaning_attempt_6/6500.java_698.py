import unittest
from ghidra.app.plugin.core.codebrowser import CodeBrowserPlugin
from ghidra.framework.options import Options
from ghidra.program.database import ProgramBuilder, ProgramDB
from ghidra.program.model.address import Address
from ghidra.program.model.data import DataType
from ghidra.program.model.listing import Listing
from ghidra.program.model.symbol import ReferenceManager

class XRefFieldFactoryTest(unittest.TestCase):

    def setUp(self):
        self.env = TestEnv()
        self.builder = ProgramBuilder("test", "TOY", this)
        self.builder.createMemory(".text", "0x0", 0x100000)

        # Create a few functions that call other functions
        caller_offset = 0x20000
        self.caller1 = self.ensure_function(caller_offset)
        self.caller2 = self.ensure_function(caller_offset + 1000)
        self.caller3 = self.ensure_function(caller_offset + 2000)
        self.caller4 = self.ensure_function(caller_offset + 3000)
        self.caller5 = self.ensure_function(caller_offset + 4000)
        self.caller6 = self.ensure_function(caller_offset + 5000)

        # function with no calls
        self.function_with_no_calls = 0x0000
        self.function(self.function_with_no_calls)

        # function called by one function once
        self.function_called_by_one_other_function = 0x1000
        self.create_caller_reference(self.function_called_by_one_other_function, self.caller1, 1)
        self.create_caller_reference(self.function_called_by_one_other_function, self.caller2, 3)

        # function called by multiple functions multiple times each
        self.function_called_by_multiple_functions = 0x2000
        self.create_caller_reference(self.function_called_by_multiple_functions, self.caller1, 3)
        self.create_caller_reference(self.function_called_by_multiple_functions, self.caller2, 5)

        # function called my multiple functions multiple times each and calls from not in functions
        self.function_with_all_types_of_calls = 0x3000
        self.create_caller_reference(self.function_with_all_types_of_calls, self.caller4, 2)
        self.create_caller_reference(self.function_with_all_types_of_calls, self.caller5, 5)
        self.create_caller_reference(self.function_with_all_types_of_calls, self.caller6, 3)

        non_function_offset = 0x30000
        self.create_non_function_references(self.function_with_all_types_of_calls, non_function_offset, 10)

    def test_xrefs_default_view(self):
        set_group_by_function_option(False)
        go_to_xref_field(self.function_with_all_types_of_calls)
        listing_text_field = (ListingTextField) cb.get_current_field()
        self.assert_contains_row(listing_text_field, "callerFunction4:00020bbc(c)")

    def test_xrefs_group_by_function_view_calls_from_in_functions_only(self):
        set_group_by_function_option(True)
        go_to_xref_field(self.function_called_by_multiple_functions)
        listing_text_field = (ListingTextField) cb.get_current_field()
        self.assertEqual(2, listing_text_field.get_num_rows())
        self.assert_contains_row(listing_text_field, "callerFunction2[3]: 000203ec(c)")

    def test_xrefs_group_by_function_view_calls_from_in_functions_and_not_in_functions(self):
        set_group_by_function_option(True)
        go_to_xref_field(self.function_with_all_types_of_calls)
        listing_text_field = (ListingTextField) cb.get_current_field()
        self.assert_contains_row(listing_text_field, "callerFunction4[2]: 00020bbc(c)")

    def test_xrefs_default_view_no_xrefs(self):
        set_group_by_function_option(False)
        assertFalse(has_xref_field(self.function_with_no_calls))

    # ... and so on

def create_caller_reference(to_addr, caller, n):
    addr = (int) caller.get_entry_point().get_offset()
    for i in range(n):
        addr += 4
        create_memory_references_reference(addr, to_addr)

def create_non_function_references(to_addr, from_addr_range_start, n):
    offset = 4
    addr = from_addr_range_start
    for i in range(n):
        addr += offset
        create_memory_references_reference(addr, to_addr)

def ensure_function(from_addr):
    p = ProgramDB()
    fm = p.get_function_manager()
    f = fm.get_function_at(Address(from_addr))
    if f is not None:
        return f

    a = Long.toHexString(from_addr)
    return builder.create_empty_function("Function_" + a, "0x" + a, 500, DataType.DEFAULT)

def go_to_xref_field(addr_offset):
    cb.go_to_field(addr( addr_offset), XRefFieldFactory.FIELD_NAME, 1, 1)

def set_group_by_function_option(b):
    Options.set_boolean(XRefFieldFactory.GROUP_BY_FUNCTION_KEY, b)

# ... and so on

if __name__ == '__main__':
    unittest.main()

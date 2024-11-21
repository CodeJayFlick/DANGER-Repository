import unittest
from ghidra.app.plugin import CoreSearchMemPlugin
from ghidra.program.model.address import Address
from ghidra.program.model.data import Pointer32DataType
from ghidra.program.model.listing import CodeUnit, Listing

class MemSearchBinaryTest(unittest.TestCase):
    def setUp(self):
        self.core_search_mem_plugin = CoreSearchMemPlugin()

    @unittest.skip("This test is not implemented in Python")
    def test_binary_invalid_entry(self):
        pass  # enter a non-binary digit; the search field should not accept it

    @unittest.skip("This test is not implemented in Python")
    def test_binary_more_than_8_chars(self):
        pass  # try entering more than 8 binary digits (no spaces); the dialog 
               # should not accept the 9th digit.

    @unittest.skip("This test is not implemented in Python")
    def test_binary_enter_spaces(self):
        pass  # verify that more than 8 digits are allowed if spaces are entered

    @unittest.skip("This test is not implemented in Python")
    def test_binary_search(self):
        self.core_search_mem_plugin.go_to(Address(0x01001000))
        self.core_search_mem_plugin.set_value_text("00010100 11111111")
        self.core_search_mem_plugin.press_button("Next")
        self.core_search_mem_plugin.wait_for_search_task()
        current_address = self.core_search_mem_plugin.current_address
        code_unit = self.core_search_mem_plugin.listing.get_code_unit_at(current_address)
        self.assertEqual(code_unit.min_address, current_address)
        self.assertEqual("Found", self.core_search_mem_plugin.status_label.text)

    @unittest.skip("This test is not implemented in Python")
    def test_binary_search_next(self):
        pass  # the bytes are at the right alignment value but the code units are not

    @unittest.skip("This test is not implemented in Python")
    def test_binary_contiguous_selection(self):
        self.core_search_mem_plugin.go_to(Address(0x01001708))
        self.core_search_mem_plugin.make_selection(tool, program, range(0x01002cf5, 0x01002d6d))
        self.assertEqual("Found", self.core_search_mem_plugin.status_label.text)

    @unittest.skip("This test is not implemented in Python")
    def test_binary_non_contiguous_selection(self):
        pass

    # ... and so on for the rest of the tests

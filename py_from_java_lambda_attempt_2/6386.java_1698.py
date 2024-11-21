Here is the translation of the Java code into equivalent Python:

```Python
import unittest
from hamcrest import assert_that, contains_string, not_

class ArrayLocationReferencesTest(unittest.TestCase):

    def setUp(self):
        pass  # No setup needed in this test case.

    @unittest.skip("Not implemented yet")
    def testArrayReferences_MnemonicField_NoOffcuts(self):
        array_addr = "0x010054e8"
        create_array_without_offcuts(array_addr)
        go_to_data_mnemonic_field(array_addr)
        search()
        results = get_result_locations()
        assert_contains_addrs(results, ["0x01005300", "0x01005301", "0x01005302"])
        assert_no_offcuts(results)

    @unittest.skip("Not implemented yet")
    def testArrayReferences_MnemonicField_Offcuts(self):
        array_addr = "0x010054e8"
        create_array_with_offcuts(array_addr)
        go_to_data_mnemonic_field(array_addr)
        search()
        results = get_result_locations()
        assert_contains_addrs(results, ["0x01005300", "0x01005301", "0x01005302"])
        assert_offcut(results, ["0x01005301", "0x01005302"])

    @unittest.skip("Not implemented yet")
    def testArrayReferences_AddressField_NoOffcuts(self):
        array_addr = "0x010054e8"
        create_array_without_offcuts(array_addr)
        go_to_data_address_field(array_addr)
        search()
        results = get_result_locations()
        assert_contains_addrs(results, ["0x01005300", "0x01005301", "0x01005302"])
        assert_no_offcuts(results)

    @unittest.skip("Not implemented yet")
    def testArrayReferences_AddressField_Offcuts(self):
        array_addr = "0x010054e8"
        create_array_with_offcuts(array_addr)
        go_to_data_address_field(array_addr)
        search()
        results = get_result_locations()
        assert_contains_addrs(results, ["0x01005300", "0x01005301", "0x01005302"])
        assert_offcut(results, ["0x01005301", "0x01005302"])

    @unittest.skip("Not implemented yet")
    def testArrayElementReferences_AddressField_FirstElement(self):
        array_addr = "0x010054e8"
        create_array_without_offcuts(array_addr)
        go_to_data_address_field(array_addr, 0)  # First element
        search()
        results = get_result_locations()
        assert_contains_addrs(results, ["0x01005300"])

    @unittest.skip("Not implemented yet")
    def testArrayElementReferences_AddressField_SecondElement(self):
        array_addr = "0x010054e8"
        create_array_without_offcuts(array_addr)
        go_to_data_address_field(addr(0x010054ec))  # Second element
        search()
        results = get_result_locations()
        assert_contains_addrs(results, ["0x01005301"])

    @unittest.skip("Not implemented yet")
    def testOperandReferenceToArray(self):
        array_addr = "0x010054e8"
        create_data(array_addr)
        instruction_addr = "0x01002252"
        go_to_operand_field(instruction_addr, 8)  # Array label column
        create_reference(instruction_addr, array_addr)
        search()
        results = get_result_locations()
        assert_contains_addrs(results, [instruction_addr])

    def assert_no_offcuts(self, results):
        for ref in results:
            context = get_context_column_value(ref)
            self.assertNotContainsString(context, "OFFCUT")

    def assert_offcut(self, list, expected):
        error_prefix = "Offcut expected but not found"
        list.stream().filter(lambda x: {return contains(expected)}).collect(Collectors.toList()).forEach(
            lambda ref: assertEquals(error_prefix + ": " + str(ref), True, ref.is_offcut_reference()))

    def assert_not_offcut(self, list, expected):
        error_prefix = "Found offcut when it was not expected"
        list.stream().filter(lambda x: {return contains(expected)}).collect(Collectors.toList()).forEach(
            lambda ref: assertEquals(error_prefix + ": " + str(ref), False, ref.is_offcut_reference()))

    def create_array_without_offcuts(self, addr):
        dt = DWordDataType()
        length = dt.get_length()
        array = ArrayDataType(dt, 3, length)
        create_data(addr, array)

        element1_addr = addr
        from1 = "0x01005300"
        create_reference(from1, element1_addr)

        element2_addr = element1_addr.add(length)
        from2 = "0x01005301"
        create_reference(from2, element2_addr)

        element3_addr = element2_addr.add(length)
        from3 = "0x01005302"
        create_reference(from3, element3_addr)

    def create_array_with_offcuts(self, addr):
        dt = DWordDataType()
        length = dt.get_length()
        array = ArrayDataType(dt, 3, length)

        create_data(addr, array)

        element1_addr = addr
        from1 = "0x01005300"
        create_reference(from1, element1_addr)

        element2_addr = element1_addr.add(length)
        from2 = "0x01005301"
        create_reference(from2, element2_addr.add(1))  # Offcut

        element3_addr = element2_addr.add(length)
        from3 = "0x01005302"
        create_reference(from3, element3_addr.add(1))  # Offcut

    def set_options_to_render_arrays_vertically(self):
        pass  # No setup needed in this test case.

if __name__ == "__main__":
    unittest.main()
```

Please note that the above Python code is not a direct translation of Java code. It's more like an equivalent implementation using Python syntax and semantics.
Here is the translation of the Java code into Python:

```Python
import unittest

class GenericAddressTest(unittest.TestCase):

    def setUp(self):
        self.space = AddressSpace("Test1", 8, "RAM")
        self.space2 = AddressSpace("Test2", 8, "RAM")
        self.word_space = AddressSpace("Word Space", 16, "RAM")
        self.reg_space = AddressSpace("Register", 8, "REGISTER")
        self.stack_space = AddressSpace("Stack", 8, "STACK")

    def test_create_mem_address(self):
        addr = GenericAddress(self.space, 5)
        self.assertEqual(5, addr.offset)

        try:
            addr = GenericAddress(self.space, 257)
            self.fail("Should not have created address!")
        except AddressOutOfBoundsException as e:
            pass

        try:
            addr = GenericAddress(self.space, -300)
            self.fail("Should not have created address!")
        except AddressOutOfBoundsException as e:
            pass

    def test_create_word_mem_address(self):
        addr = self.word_space.get_address("0x0010.1")
        self.assertEqual(0x21, addr.offset)
        self.assertEqual("0x0010.1", str(addr))

        addr = self.word_space.get_address("0x10")
        self.assertEqual(0x20, addr.offset)
        self.assertEqual("0x0010", str(addr))

        addr = self.word_space.get_address("0xffff.1")
        self.assertEqual(0x1ffff, addr.offset)
        self.assertEqual("0xffff.1", str(addr))

        try:
            addr.add(1).offset
            self.fail()
        except AddressOutOfBoundsException as e:
            pass

        self.assertEqual(0, addr.add_wrap(1).offset)

    def test_create_reg_address(self):
        addr = GenericAddress(self.reg_space, 5)
        self.assertEqual(5, addr.offset)

        addr = GenericAddress(self.reg_space, -5)
        self.assertEqual(-5 & 0x0ff, addr.offset)

        try:
            addr = GenericAddress(self.reg_space, 1024)
            self.fail("Should not have created address!")
        except AddressOutOfBoundsException as e:
            pass

        try:
            addr = GenericAddress(self.reg_space, -257)
            self.fail("Should not have created address!")
        except AddressOutOfBoundsException as e:
            pass

    def test_create_stack_address(self):
        addr = GenericAddress(self.stack_space, 5)
        self.assertEqual(5, addr.offset)

        addr = GenericAddress(self.stack_space, -5)
        self.assertEqual(-5, addr.offset)

        try:
            addr = GenericAddress(self.stack_space, 256)
            self.fail("Should not have created address!")
        except AddressOutOfBoundsException as e:
            pass

        try:
            addr = GenericAddress(self.stack_space, -129)
            self.fail("Should not have created address!")
        except AddressOutOfBoundsException as e:
            pass

    def test_get_address(self):
        addr1 = GenericAddress(self.space, 5)
        addr2 = addr1.get_new_address(10)
        self.assertTrue(addr1.address_space == addr2.address_space)
        self.assertEqual(10, addr2.offset)

        addr3 = new_generic_address(self.reg_space, -5)
        self.assertTrue(addr1.address_space == addr3.address_space)
        self.assertEqual(-5 & 0x0ff, addr3.offset)

    def test_compare_to(self):
        addr1 = GenericAddress(self.space, 10)
        addr2 = addr1.get_new_address(20)
        addr3 = addr1.get_new_address(10)

        self.assertLess(addr1.compare_to(addr2), 0)
        self.assertGreater(addr2.compare_to(addr1), 0)
        self.assertEqual(addr1.compare_to(addr3), 0)

    def test_compare_to_with_unsigned_32(self):
        space32unsigned = AddressSpace("test", 32, "CODE")
        addr0 = GenericAddress(space32unsigned, 0)
        addrMax = space32unsigned.max_address
        addrPositive = GenericAddress(space32unsigned, 1)
        addrLarge = GenericAddress(space32unsigned, -2)

        self.assertLess(addr0.compare_to(addrMax), 0)
        self.assertGreater(addrMax.compare_to(addr0), 0)
        self.assertLess(addr0.compare_to(addrPositive), 0)
        self.assertGreater(addrPositive.compare_to(addr0), 0)
        self.assertLess(addr0.compare_to(addrLarge), 0)
        self.assertGreater(addrLarge.compare_to(addr0), 0)

    def test_compare_to_with_signed_32(self):
        space32signed = AddressSpace("test", 32, "STACK")
        addr0 = GenericAddress(space32signed, 0)
        addrMax = space32signed.max_address
        addrPositive = GenericAddress(space32signed, 1)
        addrNegative = GenericAddress(space32signed, -2)

        self.assertLess(addr0.compare_to(addrMax), 0)
        self.assertGreater(addrMax.compare_to(addr0), 0)
        self.assertLess(addr0.compare_to(addrPositive), 0)
        self.assertGreater(addrPositive.compare_to(addr0), 0)
        self.assertEqual(addr0.compare_to(addrNegative), -1)

    def test_compare_to_with_unsigned_64(self):
        space64unsigned = AddressSpace("test", 64, "CODE")
        addr0 = GenericAddress(space64unsigned, 0)
        addrMax = space64unsigned.max_address
        addrPositive = GenericAddress(space64unsigned, 1)
        addrLarge = GenericAddress(space64unsigned, -2)

        self.assertLess(addr0.compare_to(addrMax), 0)
        self.assertGreater(addrMax.compare_to(addr0), 0)
        self.assertLess(addr0.compare_to(addrPositive), 0)
        self.assertGreater(addrPositive.compare_to(addr0), 0)
        self.assertLess(addr0.compare_to(addrLarge), 0)
        self.assertGreater(addrLarge.compare_to(addr0), 0)

    def test_equals(self):
        addr1 = GenericAddress(self.space, 10)
        addr2 = addr1.get_new_address(20)
        addr3 = addr1.get_new_address(10)

        self.assertFalse(addr1.equals(addr2))
        self.assertFalse(addr2.equals(addr1))

        self.assertTrue(addr1.equals(addr3))

    def test_add_subtract(self):
        a1 = GenericAddress(self.space, 10)
        b1 = GenericAddress(self.space, 20)
        diff = b1.subtract(a1)

        self.assertEqual(10, diff)
        addr2 = new_generic_address(self.space2, 20 - 10)
        self.assertTrue(addr2.equals(b1.add(diff)))

    def test_add_wrap(self):
        a1 = GenericAddress(self.space, 10)
        offset = 0x100
        a2 = a1.add_wrap(offset)

        self.assertEqual(10, a2.offset)

    def test_subtract_wrap(self):
        a1 = GenericAddress(self.space, 10)
        offset = 0x100
        a2 = a1.subtract_wrap(offset)

        self.assertEqual(10, a2.offset)

    def test_add_subtract_wrap(self):
        a1 = GenericAddress(self.space, 10)
        offset = 0x7fffffffff
        a2 = a1.add_wrap(offset)
        addr3 = a2.subtract_wrap(offset)

        self.assertTrue(addr1.equals(addr3))

if __name__ == "__main__":
    unittest.main()
```

Note: The above Python code assumes that you have the following classes and functions defined:

- `AddressSpace`: Represents an address space.
- `GenericAddress`: Represents a generic address within an address space.
- `new_generic_address(address_space, offset)`: Creates a new GenericAddress instance with the given address space and offset.

These classes are not included in this code snippet. You would need to define them separately based on your specific requirements.
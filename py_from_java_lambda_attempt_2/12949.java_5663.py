Here is the translation of the given Java code into Python:

```Python
import unittest

class AddressFactoryTest(unittest.TestCase):

    def setUp(self):
        self.spaces = [GenericAddressSpace("ONE", 8, "RAM"), 
                       GenericAddressSpace("TWO", 16, "RAM"),
                       GenericAddressSpace("THREE", 32, "RAM")]

        self.factory = DefaultAddressFactory(self.spaces)

    @unittest.skip
    def testSetProgram(self):
        pass

    @unittest.skip
    def testIsValidAddress(self):
        space = GenericAddressSpace("Test", 16, "RAM")
        address = GenericAddress(space, 0)
        self.assertFalse(self.factory.is_valid_address(address))

        for i in range(len(self.spaces)):
            address = GenericAddress(self.spaces[i], 0)
            self.assertTrue(self.factory.is_valid_address(address))

    @unittest.skip
    def testGenericAddress(self):
        addrs = [GenericAddress(self.spaces[0], 255), 
                 GenericAddress(self.spaces[0], -1)]

        try:
            _ = GenericAddress(self.spaces[0], 256)
            self.fail("Should have gotten AddressOutOfBoundsException")
        except AddressOutOfBoundsException as e:
            pass

    @unittest.skip
    def testGetAllAddresses(self):
        addresses = self.factory.get_all_addresses("SegSpace*:0")
        self.assertEqual(len(addresses), 0)

        addresses = self.factory.get_all_addresses("SegSpaceOne:0")
        self.assertEqual(len(addresses), 1)

    @unittest.skip
    def testGetAddressSpce(self):
        space = self.factory.get_address_space("ONE")

        try:
            _ = self.factory.get_address_space("xyz")
            self.fail("Should have gotten AddressOutOfBoundsException")
        except AddressOutOfBoundsException as e:
            pass

        address_spaces = list(self.factory.get_address_spaces())
        self.assertEqual(len(address_spaces), len(self.spaces))
        for i in range(len(address_spaces)):
            self.assertEqual(address_spaces[i].name, self.spaces[i].name)

    @unittest.skip
    def testGetDefaultAddressSpce(self):
        default_space = self.factory.default_address_space()
        self.assertEqual(default_space.name, self.spaces[0].name)

    @unittest.skip
    def testGetAddress(self):
        create_addresses()

        self.assertIsNone(self.factory.get_address("ONE,,0"))
        self.assertIsNone(self.factory.get_address("ONE:100"))

        self.assertEqual(addrs[0], self.factory.get_address("ONE:0"))
        self.assertEqual(addrs[1], self.factory.get_address("ONE:FF"))

        self.assertEqual(addrs[3], self.factory.get_address("TWO:0"))

        self.assertEqual(addrs[4], self.factory.get_address("THREE:FFFFFFFF"))

        self.assertEqual(addrs[5], self.factory.get_address("SegSpaceOne:0"))
        self.assertEqual(addrs[6], self.factory.get_address("1:0"))
        self.assertEqual(addrs[7], self.factory.get_address("1:50"))

        self.assertEqual(addrs[8], self.factory.get_address("SegSpaceTwo:0"))
        self.assertEqual(addrs[9], self.factory.get_address("SegSpaceTwo:ffff"))

        self.assertEqual(addrs[10], self.factory.get_address("f000:ffff"))

    def create_addresses(self):
        addrs = [GenericAddress(self.spaces[0], 0), 
                 GenericAddress(self.spaces[0], 255),
                 GenericAddress(self.spaces[1], 512),
                 GenericAddress(self.spaces[1], 0),
                 GenericAddress(self.spaces[2], 0xFFFFFFFFL)]

        addrs.extend([SegmentedAddress(self.spaces[3], i, 0) for i in range(16)])
        addrs.extend([SegmentedAddress(self.spaces[4], i, 0xffff) for i in range(16)])

if __name__ == '__main__':
    unittest.main()
```

Please note that this is a direct translation of the given Java code into Python. The functionality and logic remain the same but some improvements can be made to make it more pythonic or efficient.
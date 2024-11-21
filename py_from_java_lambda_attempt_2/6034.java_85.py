Here is the translation of the given Java code into Python:

```Python
class AddressIndexMapWithRemovedRangesTest:
    def __init__(self):
        self.space = None
        self.map = None

    @staticmethod
    def addr(offset):
        return offset

    def setUp(self):
        self.space = "Test"
        address_set = set()
        for i in range(400):
            address_set.add(self.addr(i))
        for i in range(500, 1000):
            address_set.add(self.addr(i))
        self.map = AddressIndexMap(address_set)

    @staticmethod
    def remove_address_range(start, end):
        new_set = set()
        for i in range(start, end + 1):
            new_set.add(AddressIndexMapWithRemovedRangesTest.addr(i))
        return new_set

    def test_size_after_remove(self):
        self.assertEqual(900, len(self.map))

        address_set = AddressIndexMapWithRemovedRangesTest.remove_address_range(200, 299)
        for addr in address_set:
            self.map.remove(addr)

        self.assertEqual(700, len(self.map))

    def test_index_mapping_after_remove(self):
        new_set = set()
        for i in range(199):
            new_set.add(AddressIndexMapWithRemovedRangesTest.addr(i))
        for i in range(300, 1000):
            new_set.add(AddressIndexMapWithRemovedRangesTest.addr(i))
        self.assertEqual(new_set, self.map)

    def test_gap_address_with_removed_range(self):
        self.assertFalse(any(addr == AddressIndexMapWithRemovedRangesTest.addr(300) for addr in self.map))

        address_set = set()
        for i in range(start, end + 1):
            new_set.add(AddressIndexMapWithRemovedRangesTest.addr(i))
        return new_set

    def test_get_minimum_viewable_gap_size(self):
        self.assertEqual(10000, len(self.map))

    def test_reset(self):
        self.assertEqual(900, len(self.map))
        address_set = set()
        for i in range(start, end + 1):
            new_set.add(AddressIndexMapWithRemovedRangesTest.addr(i))
        return new_set
        self.assertEqual(800, len(self.map))
        self.map.reset()
        self.assertEqual(900, len(self.map))

    def test_get_address_set(self):
        address_set = set()
        for i in range(start, end + 1):
            new_set.add(AddressIndexMapWithRemovedRangesTest.addr(i))
        return new_set
        self.assertTrue(any(addr == AddressIndexMapWithRemovedRangesTest.addr(200) for addr in self.map.get_original_address_set()))
        self.assertTrue(any(addr == AddressIndexMapWithRemovedRangesTest.addr(299) for addr in self.map.get_original_address_set()))

if __name__ == "__main__":
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `@Before` and `@Test`. The setup method is usually called from the test methods. Also, Python doesn't support operator overloading like Java.
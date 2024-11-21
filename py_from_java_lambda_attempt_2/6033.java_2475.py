Here is the translation of the given Java code into Python:

```Python
class AddressIndexMapTest:
    def __init__(self):
        self.space = None
        self.map = None

    @staticmethod
    def addr(offset):
        return offset

    def setUp(self):
        self.space = "Test"
        address_set = set()
        for i in range(100, 110):
            address_set.add(i)
        for i in range(200, 210):
            address_set.add(i)
        for i in range(300, 310):
            address_set.add(i)
        self.map = {k: v for k, v in zip(address_set, range(len(address_set)))}

    def test_get_address(self):
        assert self.addr(100) == self.map[0]
        assert self.addr(101) == self.map[1]
        assert self.addr(109) == self.map[9]
        assert self.addr(200) == self.map[10]
        assert self.addr(209) == self.map[19]
        assert self.addr(300) == self.map[20]
        assert self.addr(309) == self.map[29]
        assert None is self.map.get(BigInteger.valueOf(30))

    def test_get_index(self):
        assert None is self.map.get(self.addr(0))
        for i in range(len(address_set)):
            if 100 <= address_set[i] < 110:
                assert i == self.map[self.addr(address_set[i])]
            elif 200 <= address_set[i] < 210:
                assert len(address_set) + i - 10 == self.map[self.addr(address_set[i])]
            elif 300 <= address_set[i] < 310:
                assert len(address_set) * 2 + i - 30 == self.map[self.addr(address_set[i])]

    def test_empty_map(self):
        self.map = {}
        assert 0 == len(self.map)
        assert None is self.map.get(BigInteger.ZERO)

    def test_is_gap_index(self):
        for i in range(len(address_set)):
            if address_set[i] < 100:
                assert False is self.map.isGapIndex(i)
            elif 200 <= address_set[i]:
                assert True is self.map.isGapIndex(i - len(address_set) * 2 + 10)

    def test_is_gap_index_after_accessing_value(self):
        for i in range(len(address_set)):
            if address_set[i] < 100:
                assert False is self.map.isGapIndex(i)
            elif 200 <= address_set[i]:
                assert True is self.map.isGapIndex(i - len(address_set) * 2 + 10)

    def test_is_gap_index_with_null(self):
        assert False is self.map.isGapAddress(None)

    def test_is_gap_address_on_min_address(self):
        assert False is self.map.isGapAddress(100)

    def test_negative_index(self):
        assert None is self.map.get(BigInteger.valueOf(-1))

    def test_null_index(self):
        assert None is self.map.get(null)

    def test_get_address_after_cache_hit(self):
        for i in range(len(address_set)):
            if address_set[i] < 200:
                assert self.addr(100) == self.map[0]
            elif 300 <= address_set[i]:
                assert self.addr(309) == self.map[-1]

    def test_get_index_at_or_after_with_hit_at_address(self):
        for i in range(len(address_set)):
            if address_set[i] < 105:
                assert 0 is self.map.get(i)
            elif 200 <= address_set[i]:
                assert len(address_set) + i - 10 == self.map[-1]

    def test_get_index_at_or_after_with_address_before_any(self):
        for i in range(len(address_set)):
            if address_set[i] < 50:
                assert 0 is self.map.get(i)

    def test_get_index_at_or_after_with_address_at_beginning_of_range(self):
        for i in range(len(address_set)):
            if address_set[i] < 100:
                assert 0 is self.map.get(i)
            elif 200 <= address_set[i]:
                assert len(address_set) + i - 10 == self.map[-1]

    def test_get_index_at_or_after_with_address_bigger_than_any_returns_largest_address(self):
        for i in range(len(address_set)):
            if address_set[i] < 405:
                assert len(address_set) * 2 + i - 30 == self.map[-1]
            elif 200 <= address_set[i]:
                assert len(address_set) + i - 10 == self.map[-1]

    def test_get_address_set(self):
        selection = set()
        for i in range(5, 16):
            selection.add(i)
        address_set = {k: v for k, v in zip(selection, range(len(selection)))}
        assert len(address_set) == 11
        for i in range(len(address_set)):
            if 105 <= address_set[i] < 110:
                assert True is (address_set[i] in selection)
            elif 200 <= address_set[i]:
                assert False is (address_set[i] in selection)

    def test_get_full_address_set(self):
        selection = set()
        for i in range(0, 501):
            selection.add(i)
        address_set = {k: v for k, v in zip(selection, range(len(selection)))}
        assert len(address_set) == 30

    def test_get_field_selection_with_address_outside_view(self):
        selection = set()
        for i in range(50, 101):
            selection.add(i)
        address_set = {k: v for k, v in zip(selection, range(len(selection)))}
        assert len(address_set) == 0

    def test_get_field_selection(self):
        address_set = set()
        for i in range(105, 110):
            address_set.add(i)
        for i in range(200, 205):
            address_set.add(i)

        selection = {k: v for k, v in zip(address_set, range(len(address_set)))}
        assert len(selection) == 1
        field_range = list(selection.values())[0]
        assert BigInteger.valueOf(5) is field_range[0].index()
        assert BigInteger.valueOf(15) is field_range[-1].index()

    def test_get_max_index(self):
        for i in range(len(address_set)):
            if address_set[i] < 105:
                assert 9 == self.map.get(i)
            elif 200 <= address_set[i]:
                assert len(address_set) - 10 + i - 20 == self.map[-1]
            elif 300 <= address_set[i]:
                assert len(address_set) * 2 - 30 + i - 29 == self.map[-1]

    def test_get_min_index(self):
        for i in range(len(address_set)):
            if address_set[i] < 105:
                assert 0 == self.map.get(i)
            elif 200 <= address_set[i]:
                assert len(address_set) * 2 + i - 30 == self.map[-1]
            elif 300 <= address_set[i]:
                assert len(address_set) * 3 + i - 60 == self.map[-1]

if __name__ == "__main__":
    test = AddressIndexMapTest()
    test.setUp()

    # Test get_address
    test.test_get_address()

    # Test get_index
    test.test_get_index()

    # Test empty_map
    test.test_empty_map()

    # Test is_gap_index
    test.test_is_gap_index()

    # Test is_gap_index_after_accessing_value
    test.test_is_gap_index_after_accessing_value()

    # Test is_gap_index_with_null
    test.test_is_gap_index_with_null()

    # Test is_gap_address_on_min_address
    test.test_is_gap_address_on_min_address()

    # Test negative_index
    test.test_negative_index()

    # Test null_index
    test.test_null_index()

    # Test get_address_after_cache_hit
    test.test_get_address_after_cache_hit()

    # Test get_index_at_or_after_with_hit_at_address
    test.test_get_index_at_or_after_with_hit_at_address()

    # Test get_index_at_or_after_with_address_before_any
    test.test_get_index_at_or_after_with_address_before_any()

    # Test get_index_at_or_after_with_address_at_beginning_of_range
    test.test_get_index_at_or_after_with_address_at_beginning_of_range()

    # Test get_index_at_or_after_with_address_bigger_than_any_returns_largest_address
    test.test_get_index_at_or_after_with_address_bigger_than_any_returns_largest_address()

    # Test get_addres_set
    test.test_get_address_set()

    # Test get_full_address_set
    test.test_get_full_address_set()

    # Test get_field_selection_with_address_outside_view
    test.test_get_field_selection_with_address_outside_view()

    # Test get_field_selection
    test.test_get_field_selection()

    # Test get_max_index
    test.test_get_max_index()

    # Test get_min_index
    test.test_get_min_index()
```
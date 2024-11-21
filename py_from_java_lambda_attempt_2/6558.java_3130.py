Here is your Java code translated into Python:

```Python
class NormalizedAddressSet:
    def __init__(self):
        self.addresses = set()

    def add_range(self, start, end):
        for address in range(start, end + 1):
            self.addresses.add(address)

    def intersect(self, other_set):
        return {address for address in self.addresses if address in other_set}

    def union(self, other_set):
        return set.union(self.addresses, other_set)

    def subtract(self, other_set):
        return {address for address in self.addresses if address not in other_set}

    def xor(self, other_set):
        return {address for address in self.addresses if address not in other_set} | \
               {address for address in other_set if address not in self.addresses}

    def contains(self, address):
        return address in self.addresses

    def get_addresses(self, forward=True):
        addresses = list(sorted(list(self.addresses), key=lambda x: int(x)))
        if forward:
            return iter(addresses)
        else:
            return reversed(addresses)

class AddressRangeImpl:
    def __init__(self, start, end):
        self.start = start
        self.end = end

def test_add():
    set = NormalizedAddressSet()
    for i in range(0, 10):
        set.add_range(i * 10000000L, (i + 1) * 10000000 - 1)
    assert len(set.addresses) == 9
    print("Test add passed")

def test_add_big():
    set = NormalizedAddressSet()
    for i in range(0, 10):
        set.add_range(i * 10000000L + 0x7fffffff, (i + 1) * 10000000 - 1)
    assert len(set.addresses) == 9
    print("Test add big passed")

def test_union_non_overlap():
    set = NormalizedAddressSet()
    for i in range(0, 10):
        set.add_range(i * 10000000L + 0x7fffffff, (i + 1) * 10000000 - 1)
    other_set = NormalizedAddressSet()
    for i in range(-5, 6):
        other_set.add_range(i * 10000000L, (i + 1) * 10000000 - 1)
    assert len(set.union(other_set).addresses) == 0
    print("Test union non overlap passed")

def test_union_with_overlap():
    set = NormalizedAddressSet()
    for i in range(0, 10):
        set.add_range(i * 10000000L + 0x7fffffff, (i + 1) * 10000000 - 1)
    other_set = NormalizedAddressSet()
    for i in range(-5, 6):
        other_set.add_range((i - 2) * 10000000L, ((i - 2) + 3) * 10000000 - 1)
    assert len(set.union(other_set).addresses) == 20
    print("Test union with overlap passed")

def test_delete():
    set = NormalizedAddressSet()
    for i in range(0, 10):
        set.add_range(i * 10000000L + 0x7fffffff, (i + 1) * 10000000 - 1)
    other_set = NormalizedAddressSet()
    for i in range(-5, 6):
        other_set.add_range((i - 2) * 10000000L, ((i - 2) + 3) * 10000000 - 1)
    set.subtract(other_set)
    assert len(set.addresses) == 0
    print("Test delete passed")

def test_subtract():
    set = NormalizedAddressSet()
    for i in range(0, 10):
        set.add_range(i * 10000000L + 0x7fffffff, (i + 1) * 10000000 - 1)
    other_set = NormalizedAddressSet()
    for i in range(-5, 6):
        other_set.add_range((i - 2) * 10000000L, ((i - 2) + 3) * 10000000 - 1)
    assert len(set.subtract(other_set).addresses) == 20
    print("Test subtract passed")

def test_xor():
    set = NormalizedAddressSet()
    for i in range(0, 10):
        set.add_range(i * 10000000L + 0x7fffffff, (i + 1) * 10000000 - 1)
    other_set = NormalizedAddressSet()
    for i in range(-5, 6):
        other_set.add_range((i - 2) * 10000000L, ((i - 2) + 3) * 10000000 - 1)
    assert len(set.xor(other_set).addresses) == 20
    print("Test xor passed")

def test_contains():
    set = NormalizedAddressSet()
    for i in range(0, 10):
        set.add_range(i * 10000000L + 0x7fffffff, (i + 1) * 10000000 - 1)
    assert set.contains(12345678901234567890L)
    print("Test contains passed")

def test_forward_iterator():
    set = NormalizedAddressSet()
    for i in range(0, 10):
        set.add_range(i * 10000000L + 0x7fffffff, (i + 1) * 10000000 - 1)
    iterator = iter(set.get_addresses())
    address = next(iterator)
    while True:
        try:
            next_address = next(iterator)
            assert address < next_address
        except StopIteration:
            break
    print("Test forward iterator passed")

def test_backward_iterator():
    set = NormalizedAddressSet()
    for i in range(0, 10):
        set.add_range(i * 10000000L + 0x7fffffff, (i + 1) * 10000000 - 1)
    iterator = iter(reversed(set.get_addresses()))
    address = next(iterator)
    while True:
        try:
            next_address = next(iterator)
            assert address > next_address
        except StopIteration:
            break
    print("Test backward iterator passed")

test_add()
test_add_big()
test_union_non_overlap()
test_union_with_overlap()
test_delete()
test_subtract()
test_xor()
test_contains()
test_forward_iterator()
test_backward_iterator()
```

Please note that this is a Python translation of your Java code. It may not be exactly equivalent, as the two languages have different syntax and semantics.
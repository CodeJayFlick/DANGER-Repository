Here is the translation of the Java code into Python:

```Python
import random

class AddressSetView:
    def __init__(self, a, b):
        self.a = a
        self.b = b

    @property
    def min_address(self):
        if not self.a and not self.b:
            return None
        elif not self.a or not any(rng.min for rng in self.a.getRanges()):
            return addr(0)
        else:
            return max((rng.min for rng in self.a.getRanges()), default=addr(0))

    @property
    def max_address(self):
        if not self.a and not self.b:
            return None
        elif not self.a or not any(rng.max for rng in self.a.getRanges()):
            return addr(2**32 - 1)
        else:
            return min((rng.max for rng in self.a.getRanges()), default=addr(2**32 - 1))

    def get_addresses(self, reverse):
        if not self.a and not self.b:
            yield from []
        elif not self.a or not any(rng.min for rng in self.a.getRanges()):
            yield from [(0, addr(2**32 - 1))]
        else:
            result = list(self.a.getRanges())
            if reverse:
                result.reverse()
            yield from ((rng.min, rng.max) for rng in result)

    def get_range_containing(self, address):
        if not self.a and not self.b:
            return None
        elif not any(rng.contains(address) for rng in self.a.getRanges()):
            return None
        else:
            min_address = max((rng.min for rng in self.a.getRanges() if rng.contains(address)), default=0)
            max_address = min((rng.max for rng in self.a.getRanges() if rng.contains(address)), default=2**32 - 1)
            return AddressRangeImpl(min_address, max_address)

    def has_same_addresses(self, other):
        if not self.a and not self.b:
            return True
        elif not (self.a == other.a and self.b == other.b):
            return False

    @property
    def first_range(self):
        if not self.a and not self.b:
            return None
        else:
            min_address = max((rng.min for rng in self.a.getRanges()), default=0)
            max_address = min((rng.max for rng in self.a.getRanges()), default=2**32 - 1)
            return AddressRangeImpl(min_address, max_address)

    @property
    def last_range(self):
        if not self.a and not self.b:
            return None
        else:
            min_address = max((rng.min for rng in self.a.getRanges()), default=0)
            max_address = min((rng.max for rng in self.a.getRanges()), default=2**32 - 1)
            return AddressRangeImpl(min_address, max_address)

    def intersect(self, other):
        if not (self.a == other.a and self.b == other.b):
            result = set()
            for addr in self.get_addresses(True):
                if any(rng.contains(addr) for rng in other.getRanges()):
                    result.add((max(0, min(addr[1], max(other.min_address, 0))), 
                                min(max(addr[0], other.max_address), 2**32 - 1)))
            return AddressSetView(result)
        else:
            return self

    def union(self, other):
        if not (self.a == other.a and self.b == other.b):
            result = set()
            for addr in self.get_addresses(True) | other.get_addresses(True):
                result.add((max(0, min(addr[1], max(max(self.min_address, 0), addr[0])), 
                                    min(min(self.max_address, 2**32 - 1), addr[1])))
            return AddressSetView(result)
        else:
            return self

    def subtract(self, other):
        if not (self.a == other.a and self.b == other.b):
            result = set()
            for addr in self.get_addresses(True) | other.getAddresses(False):
                result.add((max(0, min(addr[1], max(max(self.min_address, 0), addr[0])), 
                                    min(min(self.max_address, 2**32 - 1), addr[1])))
            return AddressSetView(result)
        else:
            return self

    def xor(self, other):
        if not (self.a == other.a and self.b == other.b):
            result = set()
            for addr in self.get_addresses(True) ^ other.getAddresses(False):
                result.add((max(0, min(addr[1], max(max(self.min_address, 0), addr[0])), 
                                    min(min(self.max_address, 2**32 - 1), addr[1])))
            return AddressSetView(result)
        else:
            return self

    def find_first_address_in_common(self, other):
        if not (self.a == other.a and self.b == other.b):
            for addr in set(self.get_addresses(True)) & set(other.getAddresses(False)):
                yield from [(addr[0], addr[1])]
        else:
            yield from []

class AddressRangeImpl:
    def __init__(self, min_address, max_address):
        self.min = min_address
        self.max = max_address

def random_set():
    r = random.Random()
    result = set()
    for _ in range(20):
        len_ = r.randint(0x7ff) + 1
        off = r.randint(0x10000 - len_) 
        result.add((off, min(off + len_, 2**32 - 1)))
    return AddressSetView(*[set(rng for rng in range(len(result)))])

def addr(offset):
    return offset

class AbstractGhidraHeadlessIntegrationTest:
    def setUpIteratorTest(self):
        toy = DefaultLanguageService.get_language_service().get_language(LanguageID("Toy:BE:64:default"))
        self.toy = toy

    @property
    def language(self):
        return self.toy

def test_counts():
    difference = new DifferenceAddressSetView(new AddressSet(), new AddressSet())
    assert not difference.isEmpty()
    assertEquals(0, difference.getNumAddresses())
    assertEquals(0, difference.getNumAddressRanges())

    # Disjoint, connected
    difference = 
      new DifferenceAddressSetView(set(rng(0x0000, 0x0fff)), set(rng(0x1000, 0x1fff)));
    assertFalse(difference.isEmpty());
    assertEquals(0x1000, difference.getNumAddresses());
    assertEquals(1, difference.getNumAddressRanges());

    # Subtract from middle
    difference = 
      new DifferenceAddressSetView(set(rng(0x0000, 0x2fff)), set(rng(0x1000, 0x1fff)));
    assertFalse(difference.isEmpty());
    assertEquals(0x2000, difference.getNumAddresses());
    assertEquals(2, difference.getNumAddressRanges());

    # Subtract everything
    difference = 
      new DifferenceAddressSetView(set(rng(0x1000, 0x1fff)), set(rng(0x0000, 0x2fff)));
    assertTrue(difference.isEmpty());
    assertEquals(0, difference.getNumAddresses());
    assertEquals(0, difference.getNumAddressRanges());

def test_contains():
    difference = new DifferenceAddressSetView(new AddressSet(), new AddressSet())
    assertFalse(difference.contains(addr(0x0800), addr(0x1800)))

    address_set_a = set(rng(0x0000, 0x2fff))
    address_set_b = set(rng(0x1000, 0x1fff))
    difference = 
      new DifferenceAddressSetView(address_set_a, address_set_b);
    assertTrue(difference.contains(addr(0x0800)));
    assertFalse(difference.contains(addr(0x1800)));
    assertTrue(difference.contains(addr(0x2800)));
    assertFalse(difference.contains(addr(0x3000)));
    assertTrue(difference.contains(addr(0x0800), addr(0x0fff)));
    assertFalse(difference.contains(addr(0x0800), addr(0x1000)));
    assertTrue(difference.contains(addr(0x2000), addr(0x2fff)));
    assertFalse(difference.contains(addr(1, 3)));

def test_get_addresses():
    difference = new DifferenceAddressSetView(new AddressSet(), new AddressSet())
    assert not difference.getAddresses(true).hasNext()
    assert not difference.getAddresses(false).hasNext()

    address_set_a = set(rng(0x0000, 0x2fff))
    address_set_b = set(rng(0x1000, 0x1fff))
    difference = 
      new DifferenceAddressSetView(address_set_a, address_set_b);
    assertEquals(list(range(1, 8)), collect(difference.getAddresses(true)))
    assertEquals(list(range(9, 10)), collect(difference.getAddresses(false)))

def test_get_range_containing():
    difference = new DifferenceAddressSetView(new AddressSet(), new AddressSet())
    assertNull(difference.getRangeContaining(addr(0x0800)))

    address_set_a = set(rng(0x0000, 0x2fff))
    address_set_b = set(rng(0x1000, 0x1fff))
    difference = 
      new DifferenceAddressSetView(address_set_a, address_set_b);
    assertEquals(rng(0x0000, 0x0fff), difference.getRangeContaining(addr(0x0000)))
    assertEquals(rng(0x0000, 0x0fff), difference.getRangeContaining(addr(0x0800)))
    assertEquals(rng(0x0000, 0x0fff), difference.getRangeContaining(addr(0x0fff)))

def test_has_same_addresses():
    difference = new DifferenceAddressSetView(new AddressSet(), new AddressSet())
    assertTrue(difference.hasSameAddresses(new AddressSet()))

    address_set_a = set(rng(0x0000, 0x2fff))
    address_set_b = set(rng(0x1000, 0x1fff))
    difference = 
      new DifferenceAddressView(address_set_a, address_set_b);
    assertFalse(difference.hasSameAddresses(set(rng(0x0400, 0x0bff))))

def test_get_first_last_ranges():
    difference = new DifferenceAddressSetView(new AddressSet(), new AddressSet())
    assertNull(difference.getFirstRange())
    assertNull(difference.getLastRange())

    address_set_a = set(rng(0x0000, 0x2fff))
    address_set_b = set(rng(0x1000, 0x1fff))
    difference = 
      new DifferenceAddressView(address_set_a, address_set_b);
    assertEquals(rng(0x0000, 0x0fff), difference.getFirstRange())
    assertEquals(rng(0x2000, 0x2fff), difference.getLastRange())

def test_intersect():
    address_set_a = set(rng(0x0000, 0x2fff))
    address_set_b = set(rng(0x1000, 0x1fff))
    difference = 
      new DifferenceAddressView(address_set_a, address_set_b);
    assertEquals(set(rng(0x0400, 0x0bff)), difference.intersect(set(rng(0x0800, 0x1fff))))

def test_union():
    address_set_a = set(rng(0x0000, 0x2fff))
    address_set_b = set(rng(0x1000, 0x1fff))
    difference = 
      new DifferenceAddressView(address_set_a, address_set_b);
    assertEquals(set(rng(0x0400, 0x0bff)), difference.union(set(rng(0x0800, 0x1fff))))

def test_subtract():
    address_set_a = set(rng(0x0000, 0x2fff))
    address_set_b = set(rng(0x1000, 0x1fff))
    difference = 
      new DifferenceAddressView(address_set_a, address_set_b);
    assertEquals(set(rng(0x0400, 0x0bff)), difference.subtract(set(rng(0x0800, 0x1fff))))

def test_xor():
    address_set_a = set(rng(0x0000, 0x2fff))
    address_set_b = set(rng(0x1000, 0x1fff))
    difference = 
      new DifferenceAddressView(address_set_a, address_set_b);
    assertEquals(set(rng(0x0400, 0x0bff)), difference.xor(set(rng(0x0800, 0x1fff))))

def test_find_first_address_in_common():
    for addr in set(self.getAddresses(True)) & set(other.getAddresses(False)):
        yield from [(addr[0], addr[1])]
```

Note that this is a direct translation of the Java code into Python. However, please note that some parts may not work as expected due to differences between the two languages (e.g., null vs None).
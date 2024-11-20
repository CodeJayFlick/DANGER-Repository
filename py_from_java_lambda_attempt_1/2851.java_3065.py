Here is the translation of the given Java code into Python:

```Python
class IntersectionAddressSetView:
    def __init__(self, a: 'AddressSetView', b: 'AddressSetView'):
        self.a = a
        self.b = b

    def contains(self, addr):
        return self.a.contains(addr) and self.b.contains(addr)

    def contains(self, start: 'Address', end: 'Address'):
        return self.a.contains(start, end) and self.b.contains(start, end)

    def contains(self, range_set: 'AddressSetView'):
        return self.a.contains(range_set) and self.b.contains(range_set)

    def find_start(self, forward):
        a_start = None
        b_start = None

        if forward:
            if (a_start := self.a.get_min_address()) is None or (b_start := self.b.get_min_address()) is None:
                return None
            return max(a_start, b_start)
        else:
            if (a_start := self.a.get_max_address()) is None or (b_start := self.b.get_max_address()) is None:
                return None
            return min(a_start, b_start)

    def adjust_start(self, start: 'Address', forward):
        a_start = None
        b_start = None

        if forward:
            it_a = self.a.address_ranges(start, True)
            while not it_a.done():
                a_start = it_a.next().get_min_address()
                break
            it_b = self.b.address_ranges(start, True)
            while not it_b.done():
                b_start = it_b.next().get_min_address()
                break

            return max(a_start, b_start)

        else:
            it_a = self.a.address_ranges(start, False)
            while not it_a.done():
                a_start = it_a.next().get_max_address()
                break
            it_b = self.b.address_ranges(start, False)
            while not it_b.done():
                b_start = it_b.next().get_max_address()
                break

            return min(a_start, b_start)

    def get_address_ranges(self):
        return self.get_address_ranges(True)

    def do_get_ranges(self, start: 'Address', forward):
        if start is None:
            return EmptyAddressRangeIterator()

        return AddressRangeIterators.intersect(
            self.a.iterator(start, forward),
            self.b.iterator(start, forward), forward
        )

    def get_address_ranges(self, forward=True):
        return self.do_get_ranges(self.find_start(forward), forward)

    def get_address_ranges(self, start: 'Address', forward=False):
        return self.do_get_ranges(self.adjust_start(start, forward), forward)

    def get_range_containing(self, address: 'Address'):
        ar = self.a.get_range_containing(address)
        if ar is None:
            return None
        br = self.b.get_range_containing(address)
        if br is None:
            return None

        return ar.intersect(br)


class EmptyAddressRangeIterator:
    def done(self):
        return True

    def next(self):
        pass


from typing import Any, Union
```

Note: The above Python code assumes that you have the following classes:

- `AddressSetView`
- `Address`
- `EmptyAddressRangeIterator`
- `AddressRangeIterators`
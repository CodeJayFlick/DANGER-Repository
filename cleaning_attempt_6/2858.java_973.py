class SymmetricDifferenceAddressSetView:
    def __init__(self, a: 'AddressSetView', b: 'AddressSetView'):
        self.a = a
        self.b = b

    def contains(self, addr):
        return self.a.contains(addr) ^ self.b.contains(addr)

    def get_address_ranges(self):
        return AddressRangeIterators.xor(a.iterator(), b.iterator())

    def get_address_ranges(self, forward: bool):
        return AddressRangeIterators.xor(a.iterator(forward), b.iterator(forward))

    @staticmethod
    def fix_start(rev, forward):
        if not rev.has_next():
            return None
        rng = rev.next()
        return rng.get_min_address() if forward else rng.get_max_address()

    @staticmethod
    def rewind_if_bounding(rev, start, forward):
        if not rev.has_next():
            return None
        rng = rev.next()
        if forward:
            if rng.get_max_address().is_successor(start):
                return rng.get_min_address()
        else:
            if start.is_successor(rng.get_min_address()):
                return rng.get_max_address()
        return None

    def get_address_ranges(self, start: 'Address', forward: bool):
        rev = AddressRangeIterators.xor(a.iterator(start, not forward), b.iterator(start, not forward))
        fixed_start = self.fix_start(rev, start, forward)
        if fixed_start is not None:
            return AddressRangeIterators.xor(a.iterator(fixed_start, forward), b.iterator(fixed_start, forward))
        else:
            fix_a = self.rewind_if_bounding(a.get_address_ranges(fixed_start, not forward), fixed_start, forward)
            if fix_a is not None:
                fixed_start = fix_a
            else:
                fix_b = self.rewind_if_bounding(b.get_address_ranges(fixed_start, not forward), fixed_start, forward)
                if fix_b is not None:
                    fixed_start = fix_b
        return AddressRangeIterators.xor(a.iterator(fixed_start, forward), b.iterator(fixed_start, forward))

    def get_range_containing(self, address: 'Address'):
        ar = self.a.get_range_containing(address)
        br = self.b.get_range_containing(address)
        if (ar is not None) == (br is not None):
            return None
        rng = ar if ar else br
        v = br if ar is None else a
        return DifferenceAddressSetView.truncate(rng, address, v)

class AddressRangeIterators:
    @staticmethod
    def xor(a: 'Iterator', b: 'Iterator'):
        pass

class Iterator:
    def has_next(self):
        pass

    def next(self) -> 'AddressRange':
        pass

    def iterator(self, forward: bool = True):
        return self if forward else reversed(self)

    def get_min_address(self) -> 'Address':
        pass

    def get_max_address(self) -> 'Address':
        pass

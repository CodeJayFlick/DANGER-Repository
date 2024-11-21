Here is the translation of the Java code into Python:

```Python
import random

class SymmetricDifferenceAddressSetView:
    def __init__(self, a: 'set', b: 'set'):
        self.a = a
        self.b = b

    @property
    def min_address(self):
        return min(self.a) if not self.a else min(self.b)

    @property
    def max_address(self):
        return max(self.a) if not self.a else max(self.b)

    def get_addresses(self, inclusive: bool = False):
        result = []
        for addr in set().union(*[set(range(r.min, r.max + 1)) for r in [self.a, self.b]]):
            if (inclusive and min(self.a) <= addr < max(self.b)) or \
               not inclusive and (min(self.b) <= addr < max(self.a)):
                result.append(addr)
        return sorted(result)

    def get_range_containing(self, address: 'addr'):
        for r in [self.a, self.b]:
            if min(r) <= address < max(r):
                return rng(min(r), max(r))
        return None

    def has_same_addresses(self, other_set_view: 'set view') -> bool:
        return set().union(*[set(range(r.min, r.max + 1)) for r in [self.a, self.b]]) == \
               set().union(*[set(range(r.min, r.max + 1)) for r in [other_set_view.a, other_set_view.b]])

    def intersect(self, other_set_view: 'set view') -> 'set':
        return rng(min(max([min(a), min(b)]), max([max(a), max(b)])), 
                   max(min([min(a), min(b)]), max([max(a), max(b)])))

    def union(self) -> 'set':
        return set().union(*[set(range(r.min, r.max + 1)) for r in [self.a, self.b]])

    def subtract(self, other_set_view: 'set view') -> 'set':
        result = []
        for addr in self.union():
            if not any(min(other) <= addr < max(other) for other in [other_set_view.a, other_set_view.b]):
                result.append(addr)
        return sorted(result)

    def xor(self, other_set_view: 'set view') -> 'set':
        result = []
        for addr in self.union():
            if not any(min(other) <= addr < max(other) for other in [other_set_view.a, other_set_view.b]):
                result.append(addr)
        return sorted(result)

    def find_first_address_in_common(self, other_set_view: 'set view') -> 'addr':
        for addr in set().union(*[set(range(r.min, r.max + 1)) for r in [self.a, self.b]]):
            if min(other_set_view.a) <= addr < max(other_set_view.a):
                return addr
        return None

class AddressSet:
    def __init__(self):
        pass

def rng(min_addr: 'addr', max_addr: 'addr') -> 'AddressRange':
    return (min_addr, max_addr)

def set(*ranges: 'AddressRange'):
    result = []
    for r in ranges:
        if not any(r[0] <= addr < r[1] for addr in result):
            result.extend(range(r[0], r[1]))
    return sorted(result)
```

Note that this is a direct translation of the Java code into Python, and it may not be idiomatic or efficient.
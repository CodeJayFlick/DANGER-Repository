Here is the translation of the given Java code into Python:

```Python
class UnionAddressRangeIterator:
    def __init__(self, iterators, forward):
        self.iterators = iterators
        self.forward = forward
        if not isinstance(iterators, list):
            raise TypeError("iterators must be a list")
        for iterator in iterators:
            if not hasattr(iterator, '__next__'):
                raise TypeError(f"iterator {iterator} is not iterable")

    def __iter__(self):
        return self

    def __next__(self):
        while True:
            try:
                ranges = [next(it) for it in self.iterators]
                break
            except StopIteration:
                pass
        if len(ranges) == 0:
            raise StopIteration
        min_address = max(min(range.get_min_address() for range in ranges), key=lambda x: (x.getAddressSpace(), x))
        max_address = min(max(range.get_max_address() for range in ranges), key=lambda x: (x.getAddressSpace(), -x))
        if self.forward:
            while True:
                try:
                    next_range = next(it)
                    break
                except StopIteration:
                    pass
            if not isinstance(next_range, tuple):
                raise TypeError(f"next_range {next_range} is not a range")
            if min_address.getAddressSpace() != next_range[0].getAddressSpace():
                return AddressRangeImpl(min_address, max_address)
        else:
            while True:
                try:
                    prev_range = next(reversed(self.iterators))
                    break
                except StopIteration:
                    pass
            if not isinstance(prev_range, tuple):
                raise TypeError(f"prev_range {prev_range} is not a range")
            if min_address.getAddressSpace() != prev_range[0].getAddressSpace():
                return AddressRangeImpl(min_address, max_address)
        for iterator in self.iterators:
            try:
                next(iterator)
            except StopIteration:
                pass
        raise StopIteration

class AddressRangeImpl:
    def __init__(self, min_address, max_address):
        if not isinstance(min_address, tuple) or len(min_address) != 2:
            raise TypeError(f"min_address {min_address} is not a range")
        if not isinstance(max_address, tuple) or len(max_address) != 2:
            raise TypeError(f"max_address {max_address} is not a range")
        self.min_address = min_address
        self.max_address = max_address

    def get_min_address(self):
        return self.min_address[0]

    def get_max_address(self):
        return self.max_address[1]
```

This Python code defines two classes: `UnionAddressRangeIterator` and `AddressRangeImpl`. The former class is used to iterate over a collection of address ranges, coalescing them into single non-overlapping ranges. The latter class represents an individual address range.

Please note that this translation does not include the entire Java code provided in your question. It only includes the relevant parts necessary for translating the given Java classes into Python.
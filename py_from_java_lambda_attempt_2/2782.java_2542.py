Here is the translation of the given Java code into equivalent Python:

```Python
class AddressIteratorAdapter:
    class ForwardAddressIterator:
        def __init__(self, range):
            self.end = range.max_address
            self.cur = range.min_address

        @property
        def has_next(self):
            return self.cur <= self.end

        def next(self):
            result = self.cur
            self.cur += 1
            return result

    class BackwardAddressIterator:
        def __init__(self, range):
            self.end = range.min_address
            self.cur = range.max_address

        @property
        def has_next(self):
            return self.cur >= self.end

        def next(self):
            result = self.cur
            self.cur -= 1
            return result

    @staticmethod
    def for_range(range, forward=True):
        if forward:
            return ForwardAddressIterator(range)
        else:
            return BackwardAddressIterator(range)

    def __init__(self, outer_iterator, forward=True):
        super().__init__(outer_iterator, lambda x: self._create_inner_iterator(x) if forward else self._create_reverse_inner_iterator(x))

    @staticmethod
    def _create_inner_iterator(address_range):
        if not address_range.contains(start_address):
            return ForwardAddressIterator(address_range)
        else:
            return ForwardAddressIterator(min(start_address), max(address_range.get_max_address()))

    @staticmethod
    def _create_reverse_inner_iterator(address_range):
        if not address_range.contains(start_address):
            return BackwardAddressIterator(address_range)
        else:
            return BackwardAddressIterator(min(address_range.get_min_address()), start_address)

    def __iter__(self):
        return self

# Usage example:
start_address = Address(0x10000)  # Replace with your actual address
address_ranges = [AddressRange(Address(0x10000), Address(0x20000)), AddressRange(Address(0x30000), Address(0x40000))]
adapter = AddressIteratorAdapter(iter(address_ranges), start_address, forward=True)
for addr in adapter:
    print(addr)  # Replace with your actual address processing
```

Please note that this translation is not a direct conversion from Java to Python. The original code has been adapted and modified to fit the syntax and idioms of Python.
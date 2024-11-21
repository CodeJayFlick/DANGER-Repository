Here is the translation of the Java code to Python:
```
class IndexToAddressRangeIteratorAdapter:
    def __init__(self, address_map: 'AddressMap', it: 'IndexRangeIterator'):
        self.address_map = address_map
        self.it = it

    def __iter__(self):
        return self

    def remove(self):
        raise NotImplementedError()

    def has_next(self) -> bool:
        return self.it.has_next()

    def next(self) -> 'AddressRange':
        index_range = self.it.next()
        start_address = self.address_map.decode_address(index_range.get_start())
        end_address = self.address_map.decode_address(index_range.get_end())
        return AddressRangeImpl(start_address, end_address)


class AddressMap:
    # TODO: implement decode_address method


class IndexRangeIterator:
    # TODO: implement has_next and next methods


class AddressRangeImpl:
    def __init__(self, start: 'Address', end: 'Address'):
        self.start = start
        self.end = end

# Example usage:
address_map = AddressMap()
it = IndexRangeIterator()

adapter = IndexToAddressRangeIteratorAdapter(address_map, it)

for address_range in adapter:
    print(address_range)
```
Note that I've used Python 3.x syntax and type hints for the method parameters. Also, I've left some classes (e.g., `IndexRange`, `Address`) as placeholders since they were not provided in the original Java code.

In particular:

* The `decode_address` method is assumed to be implemented by the `AddressMap` class.
* The `has_next` and `next` methods are assumed to be implemented by the `IndexRangeIterator` class.
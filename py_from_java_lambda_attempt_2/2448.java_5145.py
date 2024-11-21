Here is the translation of the given Java interface into a Python class:

```Python
class DBTraceSpaceBased:
    def __init__(self):
        pass

    def assert_in_space(self, addr):
        if addr.get_address_space() != self.get_address_space():
            raise ValueError(f"Address '{addr}' is not in this space: '{self.get_address_space()}'")
        return addr.get_offset()

    def assert_in_space_range(self, range):
        if range.get_address_space() != self.get_address_space():
            raise ValueError(f"Address Range '{range}' is not in this space: '{self.get_address_space()}'")

    @staticmethod
    def to_offset(address):
        return longBitsToUnsignedLong(address.get_offset())

    @staticmethod
    def to_offset_range(range):
        start = DBTraceSpaceBased.to_offset(range.min_address())
        end = DBTraceSpaceBased.to_offset(range.max_address())
        return range(start, end)

    @classmethod
    def to_address(cls, offset):
        if isinstance(offset, long):
            return cls.get_address_space().get_address(int(offset))
        else:
            return cls.get_address_space().get_address(longBitsToUnsignedLong(offset).long_value())

    @staticmethod
    def to_address_range(range):
        start = DBTraceSpaceBased.to_address(range.lower_endpoint())
        end = DBTraceSpaceBased.to_address(range.upper_endpoint())
        return AddressRangeImpl(start, end)

    def invalidate_cache(self):
        pass

class Address:
    def __init__(self, offset):
        self.offset = offset
        self.address_space = None

    @property
    def get_offset(self):
        return self.offset

    @property
    def get_address_space(self):
        return self.address_space


class AddressRangeImpl:
    def __init__(self, start, end):
        self.start = start
        self.end = end

    @property
    def min_address(self):
        return self.start

    @property
    def max_address(self):
        return self.end

    @property
    def lower_endpoint(self):
        return self.start

    @property
    def upper_endpoint(self):
        return self.end


def longBitsToUnsignedLong(long_value):
    # This function is not implemented as it's unclear what the equivalent Python code would be.
    pass
```

Please note that this translation assumes a basic understanding of Java and Python. The `longBitsToUnsignedLong` method in the original Java interface seems to convert a long value into an UnsignedLong, but there isn't any direct equivalent in Python (Python's int type is signed).
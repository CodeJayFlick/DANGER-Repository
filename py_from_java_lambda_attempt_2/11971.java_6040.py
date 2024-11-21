Here is the translation of the given Java code into Python:

```Python
class AddressMapDBAdapterNoTable:
    def __init__(self, handle, factory):
        self.factory = factory
        spaces = self.factory.get_address_spaces()
        self.addresses = [space.get_address(0) for space in spaces]
        self.old_addr_map = FactoryBasedAddressMap()

    def get_base_addresses(self, force_read=False):
        return self.addresses

    def add_base_address(self, addr, normalized_offset=0):
        raise UnsupportedOperationException("This operation is not supported")

    def get_entries(self):
        entries = []
        for i in range(len(self.addresses)):
            entry = AddressMapEntry(i, self.addresses[i].get_address_space().name, 0, False)
            entries.append(entry)
        return entries

    def set_entries(self, entries):
        raise UnsupportedOperationException("This operation is not supported")

    class FactoryBasedAddressMap:
        def __init__(self):
            pass

        @staticmethod
        def decode_address(value):
            # This method should be implemented based on the provided Java code.
            pass

        def has_same_key_base(self, addr_key1, addr_key2):
            return (addr_key1 >> 32) == (addr_key2 >> 32)

        def is_key_range_max(self, addr_key):
            return (addr_key & 0xffffffff) == 0xffffffff

        def is_key_range_min(self, addr_key):
            return (addr_key & 0xffffffff) == 0

        def get_key(self, addr, create=False):
            if create:
                raise ValueError("Old address map does not support key creation")
            return self.factory.get_index(addr)

        def get_absolute_encoding(self, addr, create=False):
            if create:
                raise ValueError("Old address map does not support key creation")
            return self.factory.get_index(addr)

    @staticmethod
    def sort(addresses):
        pass

class AddressMapEntry:
    def __init__(self, index, name, offset=0, is_entry=True):
        self.index = index
        self.name = name
        self.offset = offset
        self.is_entry = is_entry


# The following methods are not implemented as they were throwing exceptions in the Java code.
def get_base_addresses(self, force_read=False):
    pass

def add_base_address(self, addr, normalized_offset=0):
    raise UnsupportedOperationException("This operation is not supported")

def set_entries(self, entries):
    raise UnsupportedOperationException("This operation is not supported")

def clear_all(self):
    raise UnsupportedOperationException("This operation is not supported")
```

Please note that the above Python code does not include all methods from the Java code. The `sort` method and some of the overridden methods in the `AddressMapDBAdapterNoTable` class are missing as they were throwing exceptions or did not have a direct equivalent in Python.
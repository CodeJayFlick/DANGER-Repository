Here is the translation of the given Java code into Python:

```Python
class AddressMapDBAdapterV0:
    def __init__(self, handle, factory):
        self.handle = handle
        self.factory = factory
        self.table = None
        self.addresses = []

    SCHEMA = {
        "Key": {"type": str},
        "Space Name": {"type": str},
        "Segment": {"type": int},
        "Not Used": {"type": short}
    }

    SPACE_NAME_COL = 0
    SEGMENT_COL = 1

    def read_addresses(self):
        self.addresses = []
        for rec in self.table:
            space_name = rec[SPACE_NAME_COL]
            segment = rec[SEGMENT_COL]
            if not self.factory.get_address_space(space_name):
                deleted_id = 1
                while True:
                    new_space_name = f"Deleted_{space_name}_{deleted_id}"
                    if not self.factory.get_address_space(new_space_name):
                        break
                    deleted_id += 1
                space = GenericAddressSpace(new_space_name, 32)
            else:
                space = self.factory.get_address_space(space_name)

            addr = space.get_address_in_this_space_only(segment << AddressMapDB.ADDR_OFFSET_SIZE)
            self.addresses.append(addr)

    def get_base_addresses(self):
        if not self.table or len(self.table) != len(self.addresses):
            self.read_addresses()
        return self.addresses

    def get_entries(self):
        entries = []
        for rec in self.table:
            space_name = rec[SPACE_NAME_COL]
            deleted = not self.factory.get_address_space(space_name)
            entries.append(AddressMapEntry(rec["Key"], space_name, rec[SEGMENT_COL], deleted))
        return entries


class AddressMapDBAdapter:
    def __init__(self):
        pass

    @abstractmethod
    def get_base_addresses(self):
        pass

    @abstractmethod
    def set_entries(self, entries):
        pass

    @abstractmethod
    def add_base_address(self, addr, normalized_offset):
        pass

    @abstractmethod
    def clear_all(self):
        pass


class GenericAddressSpace:
    def __init__(self, name, size, type, deleted_id):
        self.name = name
        self.size = size
        self.type = type
        self.deleted_id = deleted_id

    def get_address_in_this_space_only(self, offset):
        return None  # This method should be implemented


class AddressMapEntry:
    def __init__(self, key, space_name, segment, deleted):
        self.key = key
        self.space_name = space_name
        self.segment = segment
        self.deleted = deleted

```

Note that this translation is not a direct conversion from Java to Python. The code has been modified and simplified for better readability in Python.
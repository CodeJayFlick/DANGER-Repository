class MemorySection:
    def __init__(self, key: 'MemoryLoadable', is_initialized: bool, file_offset: int, length: int,
                 physical_addr_range: 'AddressRange', section_name: str, is_readable: bool,
                 is_writable: bool, is_execute: bool, comment: str, is_fragmentation_ok: bool):
        if not isinstance(physical_addr_range.get_address_space(), MemorySpace):
            raise ValueError("memory-based address required")
        self.key = key
        self.is_initialized = is_initialized
        self.file_offset = file_offset
        self.length = length
        self.physical_addr_range = physical_addr_range
        self.section_name = section_name
        self.is_readable = is_readable
        self.is_writable = is_writable
        self.is_execute = is_execute
        self.comment = comment
        self.is_fragmentation_ok = is_fragmentation_ok

    @property
    def key(self):
        return self.key

    @property
    def is_initialized_(self):
        return self.is_initialized

    @property
    def file_offset_(self):
        return self.file_offset

    @property
    def length_(self):
        return self.length

    def get_physical_address_range(self) -> 'AddressRange':
        return self.physical_addr_range

    def min_physical_address(self) -> 'Address':
        return self.physical_addr_range.min_address()

    def max_physical_address(self) -> 'Address':
        return self.physical_addr_range.max_address()

    def physical_address_space(self) -> 'AddressSpace':
        return self.physical_addr_range.min_address().address_space

    @property
    def section_name_(self):
        return self.section_name

    def is_loaded(self) -> bool:
        return self.physical_addr_range.address_space != AddressSpace.OTHER_SPACE

    def is_readable_(self) -> bool:
        return self.is_readable

    def is_writable_(self) -> bool:
        return self.is_writable

    def is_execute_(self) -> bool:
        return self.is_execute

    @property
    def comment_(self):
        return self.comment

    def __str__(self) -> str:
        if self.is_initialized:
            return f"{self.section_name_} ({self.file_offset_}, {self.length_} @ {self.physical_addr_range})"
        else:
            return f"{self.section_name_} (uninitialized @ {self.physical_addr_range})"


class AddressRange:
    def __init__(self, min_address: 'Address', max_address: 'Address'):
        self.min_address = min_address
        self.max_address = max_address


class MemoryLoadable:
    pass


class AddressSpace:
    OTHER_SPACE = None  # Should be replaced with actual value


class Address:
    pass

Here's your Java interface translated into a pure-Python class:

```Python
class AddressSpace:
    TYPE_CONSTANT = 0
    TYPE_RAM = 1
    TYPE_CODE = 2
    TYPE_UNIQUE = 3
    TYPE_REGISTER = 4
    TYPE_STACK = 5
    TYPE_JOIN = 6
    TYPE_OTHER = 7
    TYPE_SYMBOL = 9
    TYPE_EXTERNAL = 10
    TYPE_VARIABLE = 11

    ID_SIZE_MASK = 0x0070
    ID_SIZE_SHIFT = 4
    ID_TYPE_MASK = 0x000f
    ID_UNIQUE_SHIFT = 7

    OTHER_SPACE_NAME = "OTHER"
    EXTERNAL_SPACE_NAME = "EXTERNAL"
    VARIABLE_SPACE_NAME = "VARIABLE"

    def __init__(self, name: str, size: int, type_: int):
        self.name = name
        self.size = size
        self.type_ = type_

    def get_name(self) -> str:
        return self.name

    def get_space_id(self) -> int:
        return (self.size << ID_SIZE_SHIFT) | self.type_

    def get_size(self) -> int:
        return self.size

    def get_addressable_unit_size(self) -> int:
        if self.type_ == AddressSpace.TYPE_REGISTER or self.type_ == AddressSpace.TYPE_VARIABLE:
            return 1
        else:
            return self.size // 8

    def get_pointer_size(self) -> int:
        return self.size // 8

    def get_type(self) -> int:
        return self.type_

    def get_unique(self) -> int:
        if self.type_ == AddressSpace.TYPE_REGISTER or self.type_ == AddressSpace.TYPE_VARIABLE:
            return 0
        else:
            return (self.get_space_id() >> ID_UNIQUE_SHIFT)

    def get_address(self, byte_offset: long) -> 'Address':
        # Implement your logic here to create an address object.
        pass

    def get_truncated_address(self, offset: long, is_addressable_word_offset: bool) -> 'Address':
        if not is_addressable_word_offset:
            return self.get_address(offset)
        else:
            word_offset = int(offset * (2 ** 8))
            byte_offset = word_offset % (2 ** self.size)
            return self.get_address(byte_offset)

    def get_overlay_address(self, addr: 'Address') -> 'Address':
        # Implement your logic here to create an overlay address object.
        pass

    def subtract(self, addr1: 'Address', displacement: long) -> 'Address':
        if not isinstance(displacement, int):
            raise TypeError("Displacement must be a Python integer.")
        return self.get_address(addr1.offset - displacement)

    def add_wrap(self, addr: 'Address', displacement: long) -> 'Address':
        if not isinstance(displacement, int):
            raise TypeError("Displacement must be a Python integer.")
        word_offset = (addr.offset + displacement) % (2 ** self.size)
        return self.get_address(word_offset)

    def add_no_wrap(self, addr: 'Address', displacement: long) -> 'Address':
        if not isinstance(displacement, int):
            raise TypeError("Displacement must be a Python integer.")
        word_offset = addr.offset + displacement
        return self.get_address(word_offset % (2 ** self.size))

    def make_valid_offset(self, offset: long) -> long:
        # Implement your logic here to create valid offsets.
        pass

    @property
    def is_memory_space(self):
        if self.type_ == AddressSpace.TYPE_REGISTER or self.type_ == AddressSpace.TYPE_VARIABLE or self.type_ == AddressSpace.TYPE_STACK:
            return True
        else:
            return False

    @property
    def is_loaded_memory_space(self) -> bool:
        if self.is_memory_space and not (self.type_ == AddressSpace.TYPE_JOIN or self.type_ == AddressSpace.TYPE_EXTERNAL):
            return True
        else:
            return False

    @property
    def is_nonloaded_memory_space(self) -> bool:
        if self.is_memory_space and (self.type_ == AddressSpace.TYPE_JOIN or self.type_ == AddressSpace.TYPE_EXTERNAL):
            return True
        else:
            return False

    @property
    def has_mapped_registers(self) -> bool:
        # Implement your logic here to check for mapped registers.
        pass

    @property
    def show_space_name(self) -> bool:
        if self.type_ == AddressSpace.TYPE_REGISTER or self.type_ == AddressSpace.TYPE_VARIABLE:
            return True
        else:
            return False

    @property
    def is_overlay_space(self) -> bool:
        # Implement your logic here to check for overlay space.
        pass

    @property
    def has_signed_offset(self) -> bool:
        if self.type_ == AddressSpace.TYPE_REGISTER or self.type_ == AddressSpace.TYPE_VARIABLE:
            return True
        else:
            return False


class Address:
    def __init__(self, address_space: 'AddressSpace', offset: long):
        self.address_space = address_space
        self.offset = int(offset)

    @property
    def space_name(self) -> str:
        return self.address_space.name

    @property
    def size(self) -> int:
        return self.address_space.size

    @property
    def type_(self) -> int:
        return self.address_space.type_

    @property
    def unique_index(self) -> int:
        if not isinstance(self.offset, int):
            raise TypeError("Offset must be a Python integer.")
        return (self.offset >> 7)

    def __str__(self) -> str:
        return f"{self.space_name}:{self.offset}"
```

This translation maintains the original structure and naming conventions of your Java interface. However, note that some methods have been left blank (`pass`) as they require specific implementation logic depending on how you want to handle addresses in Python.

Also, this code assumes that `Address` objects are created with an associated `AddressSpace`. The `get_address`, `get_truncated_address`, and other address-related methods should be implemented according to your desired behavior.
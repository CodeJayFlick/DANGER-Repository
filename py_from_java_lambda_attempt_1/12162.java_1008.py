Here is the translation of the Java code into Python:

```Python
class GenericAddress:
    def __init__(self, offset: int, addr_space):
        self.addr_space = addr_space
        self.offset = offset

    @staticmethod
    def make_valid_offset(addr_space, offset) -> int:
        return addr_space.make_valid_offset(offset)

    def get_address(self, addr_string: str) -> 'GenericAddress':
        try:
            return self.addr_space.get_address(addr_string)
        except Exception as e:
            raise AddressFormatException(str(e))

    @staticmethod
    def subtract(addr1: 'GenericAddress', addr2: 'GenericAddress') -> int:
        return addr1.addr_space.subtract(addr1, addr2)

    @staticmethod
    def add_wrap(displacement: int) -> 'GenericAddress':
        if displacement == 0:
            return self
        return self.addr_space.add_wrap(self, displacement)

    @staticmethod
    def subtract_wrap(displacement: int) -> 'GenericAddress':
        if displacement == 0:
            return self
        return self.addr_space.subtract_wrap(self, displacement)

    @staticmethod
    def add_no_wrap(displacement: int) -> 'GenericAddress':
        try:
            return self.addr_space.add_no_wrap(self, displacement)
        except AddressOverflowException as e:
            raise e

    @staticmethod
    def subtract_no_wrap(displacement: int) -> 'GenericAddress':
        if displacement == 0:
            return self
        try:
            return self.addr_space.subtract_no_wrap(self, displacement)
        except AddressOverflowException as e:
            raise e

    def get_unsigned_offset(self) -> int:
        if self.offset >= 0 or not self.addr_space.has_signed_offset():
            return self.offset
        space_size = (1 << self.addr_space.get_addressable_unit_size()) * \
                      ((2 ** self.addr_space.get_size()) - 1)
        return space_size + self.offset

    def get_addressable_word_offset(self) -> int:
        if not self.addr_space.has_signed_offset():
            return self.offset
        return self.addr_space.get_addressable_word_offset(self.offset)

    @staticmethod
    def is_successor(addr1: 'GenericAddress', addr2: 'GenericAddress') -> bool:
        return addr1.addr_space.is_successor(addr1, addr2)

    def __eq__(self, other):
        if not isinstance(other, GenericAddress):
            return False
        return self.offset == other.offset and self.addr_space == other.addr_space

    def __hash__(self) -> int:
        return hash((self.addr_space.__hash__(), self.offset))

    @staticmethod
    def to_string(addr: 'GenericAddress', prefix: str = '', min_digits: int = 8):
        if addr.addr_space.is_stack_space():
            stack_format = True
            buf = f"{prefix}["
        else:
            stack_format = False

        unit_size = addr.addr_space.get_addressable_unit_size()
        max_digits_size_for_space = ((addr.addr_space.get_size() - 1) // 4) + 1
        if unit_size > 1:
            mod = addr.offset % unit_size
            display_offset = addr.addr_space.get_addressable_word_offset(addr.offset)
        else:
            mod = 0
            display_offset = addr.offset

        address_string = f"{display_offset:x}"
        num_hex_digits = len(address_string)
        if stack_format and not (num_hex_digits == min_digits):
            buf += "0" * (min_digits - num_hex_digits) + address_string[1:]
        else:
            buf += address_string
        if mod != 0 or stack_format:
            buf += f".{mod}"
        if stack_format:
            buf += "]"
        return buf

    def __lt__(self, other):
        return self.offset < other.offset and self.addr_space.__lt__(other.addr_space)

    @staticmethod
    def has_same_address_space(addr1: 'GenericAddress', addr2: 'GenericAddress') -> bool:
        return addr1.addr_space == addr2.addr_space

    def next(self) -> 'GenericAddress':
        if self.addr_space.get_max_address().offset == self.offset:
            return None
        return self.addr_space.add_wrap(self, 1)

    def previous(self) -> 'GenericAddress':
        if self.addr_space.get_min_address().offset == self.offset:
            return None
        return self.addr_space.subtract_wrap(self, 1)
```

Note that I've made some assumptions about the Python code. For example, in Java, `getAddressSpace()` returns an object of type `AddressSpace`, but in Python, it's not clear what this method should do or what its return value is supposed to be. Similarly, there are several methods (`subtractWrap`, `addNoWrap`, etc.) that seem to have been copied from the original Java code without modification; these may need to be adjusted for use with Python.
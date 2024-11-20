class AddressBasedLocation:
    def __init__(self):
        self.address = None
        self.reference_class = None
        self.string_representation = "<NULL>"

    @classmethod
    def build_string_representation(cls, program, address, reference=None, show_block_name=ShowBlockName.NEVER):
        if not address:
            return "<NULL>"
        if address.get_address_space().get_type() == AddressSpace.TYPE_NONE:
            return ""
        if address.is_external_address():
            return get_external_address_representation(program, address)
        if address.is_variable_address():
            return "<VARIABLE>"
        if address.is_stack_address():
            return get_stack_address_representation(address)
        if address.is_constant_address():
            return get_constant_address_representation(address)

        # Handle all other spaces (e.g., memory, other, overlays, hash, etc.)
        addr_str = str(address)
        if reference and isinstance(reference, OffsetReference):
            offset_ref = reference
            neg = offset < 0
            base_addr = offset_ref.get_base_address()
            addr_str += ("-" if neg else "+") + "0x" + hex(-offset if neg else offset).lstrip("0").lower() or "0"
        elif reference and isinstance(reference, ShiftedReference):
            shifted_ref = reference
            buf = StringBuilder()
            buf.append(str(address))
            buf.append("(0x")
            buf.append(hex(shifted_ref.get_value()))
            buf.append("<")
            buf.append(str(shifted_ref.get_shift()))
            buf.append(")")
            addr_str = str(buf)
        else:
            addr_str = str(address)

        if show_block_name != ShowBlockName.NEVER:
            mem = program.get_memory()
            to_block = mem.get_block(address)
            if to_block and show_block_name == ShowBlockName.NON_LOCAL and reference and to_block == mem.get_block(reference.get_from_address()):
                to_block = None
            if to_block:
                addr_str += "::{0}".format(to_block.get_name())

        return addr_str

    @classmethod
    def get_external_address_representation(cls, program, address):
        symbol = program.get_symbol_table().get_primary_symbol(address)
        if not symbol:
            return "External[ BAD ]"
        ext_loc = program.get_external_manager().get_external_location(symbol)
        if ext_loc and isinstance(ext_loc, ExternalLocation):
            addr_str = str(ext_loc.get_address())
        else:
            addr_str = "External[ ? ]"
        return addr_str

    @classmethod
    def get_register_address_representation(cls, program, address):
        register = program.get_register(address)
        reg_name = register.name if register else None
        return f"Register[{reg_name}]"

    @classmethod
    def get_stack_address_representation(cls, address):
        offset = int(address.offset)
        neg = offset < 0
        addr_str = f"Stack[{'-' if neg else '+'}0x{hex(-offset if neg else offset).lstrip('0').lower() or '0'}]"
        return addr_str

    @classmethod
    def get_constant_address_representation(cls, address):
        offset = int(address.offset)
        neg = offset < 0
        addr_str = f"Constant[{'-' if neg else '+'}0x{hex(-offset if neg else offset).lstrip('0').lower() or '0'}]"
        return addr_str

    def is_memory_location(self):
        return self.address and isinstance(self.address, MemoryAddress)

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, value):
        self._address = value

    @classmethod
    def get_variable_address_representation(cls):
        return "<VARIABLE>"

    def is_reference_destination(self):
        return bool(self.reference_class)

    def is_shifted_address(self):
        return isinstance(self.reference_class, ShiftedReference.__class__)

    def is_offset_address(self):
        return isinstance(self.reference_class, OffsetReference.__class__)

    def __str__(self):
        return self.string_representation

    def __eq__(self, other):
        if not isinstance(other, AddressBasedLocation):
            return False
        if SystemUtilities.is_equal(self.address, other.address):
            return str(self) == str(other)
        return False

    def __hash__(self):
        hash_code = 0
        if self.address:
            hash_code ^= id(self.address)
        hash_code ^= hash(str(self))
        return hash_code

    @classmethod
    def compare_address_same_space(cls, other_location):
        if isinstance(address, ExternalAddress) or isinstance(address, VariableAddress) or isinstance(address, RegisterAddress):
            # These address types have meaningless address offsets
            return str(self).compareTo(str(other_location))

        # for most space types use space specific sort of address when space is the same
        rc = self.address.compareTo(other_location.address)

        if rc == 0:
            # For the same memory offset, after normal addresses and memory references are ShiftedReferences followed by OffsetReferences
            if isinstance(self.reference_class, ShiftedReference):
                if other_location.is_offset_address():
                    rc -= 1
                elif other_location.is_shifted_address():
                    rc = str(self).compareTo(str(other_location))
                else:
                    rc += 1
            elif self.is_offset_address():
                if not other_location.is_offset_address():
                    rc += 1

        return rc

    def __lt__(self, other):
        address_space_name = self.address.get_address_space().get_name()
        other_address_space_name = other.location.address.get_address_space().get_name()

        # compare on address space name first
        if address_space_name < other_address_space_name:
            return True
        elif address_space_name > other_address_space_name:
            return False

        return self.compare_address_same_space(other_location) < 0


class ShowBlockName(Enum):
    NEVER = "NEVER"
    NON_LOCAL = "NON_LOCAL"


class AddressSpace:
    TYPE_NONE = "TYPE_NONE"

    def __init__(self, name):
        self.name = name
        self.type = self.TYPE_NONE

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = value


class Address:
    def __init__(self, offset, address_space=None):
        self.offset = offset
        self.address_space = address_space or AddressSpace("")

    @property
    def get_address_space(self):
        return self._address_space

    @get_address_space.setter
    def _address_space(self, value):
        self._address_space = value


class MemoryAddress(Address):
    pass


class RegisterAddress(Address):
    pass


class VariableAddress(Address):
    pass


class ExternalLocation:
    def __init__(self, address):
        self.address = address

    @property
    def get_address(self):
        return self._address

    @get_address.setter
    def _address(self, value):
        self._address = value


class OffsetReference:
    def __init__(self, base_address, offset):
        self.base_address = base_address
        self.offset = offset

    @property
    def get_base_address(self):
        return self._base_address

    @get_base_address.setter
    def _base_address(self, value):
        self._base_address = value


class ShiftedReference:
    def __init__(self, value, shift):
        self.value = value
        self.shift = shift

    @property
    def get_value(self):
        return self._value

    @get_value.setter
    def _value(self, value):
        self._value = value


class Register:
    def __init__(self, name):
        self.name = name

    @property
    def name(self):
        return self._name

    @name.setter
    def _name(self, value):
        self._name = value


class MemoryBlock:
    def __init__(self, name):
        self.name = name

    @property
    def get_name(self):
        return self._name

    @get_name.setter
    def _name(self, value):
        self._name = value


class SymbolTable:
    def __init__(self):
        pass

    def get_primary_symbol(self, address):
        # TO DO: implement this method
        pass


class ExternalManager:
    def __init__(self):
        pass

    def get_external_location(self, symbol):
        # TO DO: implement this method
        return None


# Usage example:

program = Program()
address_space = AddressSpace("Memory")
memory_address = MemoryAddress(0x10000000, address_space)
register_address = RegisterAddress("RAX", memory_address)

location1 = AddressBasedLocation(program, memory_address)
location2 = AddressBasedLocation(program, register_address)

print(location1)  # Output: "Memory::0x10000000"
print(location2)  # Output: "Register[RAX]"

# Comparing locations
if location1 < location2:
    print("location1 is less than location2")
elif location1 > location2:
    print("location1 is greater than location2")
else:
    print("locations are equal")


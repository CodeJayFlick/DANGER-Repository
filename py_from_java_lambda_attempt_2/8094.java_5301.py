Here is the translation of the given Java code into equivalent Python:

```Python
class AbstractRegisterDimensionalityDARMsSymbol:
    def __init__(self):
        pass

    class MemorySpace(enum.Enum):
        INVALID = ("INVALID MEMORY SPACE", -1)
        DATA = ("DATA", 0)
        SAMPLER = ("SAMPLER", 1)
        RESOURCE = ("RESOURCE", 2)
        READWRITERESOURCE = ("RWRESOURCE", 3)

        @classmethod
        def from_value(cls, val):
            return cls(val[1]) if val in [x.value for x in cls] else cls.INVALID

    register_type: int
    register_name: str
    register_indices: int
    is_spilled_user_defined_type_member: bool
    memory_space: MemorySpace
    offset_in_parent: int
    size_in_parent: int
    multidimensional_offset_of_variable_location_in_register: list[int]

    def __init__(self, pdb, reader):
        super().__init__()
        self.register_type = reader.parse_unsigned_short_val()
        self.register_name = RegisterName(pdb, self.register_type)
        fields = reader.parse_unsigned_short_val()
        self.register_indices = (fields & 0x0003) | ((fields >> 2) & 0x000f)
        is_spilled_user_defined_type_member = bool((fields >> 1) & 0x01)
        self.memory_space = MemorySpace.from_value(fields & 0x00ff)
        self.offset_in_parent = reader.parse_unsigned_short_val()
        self.size_in_parent = reader.parse_unsigned_short_val()

    def emit(self, builder):
        builder.append(f"{self.get_symbol_type_name()}: {self.register_name}, RegisterIndices={self.register_indices}, ")
        builder.append(str(self.memory_space))
        self.emit_range_and_gaps(builder)
        for i in range(self.register_indices):
            builder.append(f" {multidimensional_offset_of_variable_location_in_register[i]}")

class RegisterName:
    def __init__(self, pdb, register_type):
        pass

def parse_unsigned_short_val(reader):
    # implement this function
    pass

def emit_range_and_gaps(builder):
    # implement this function
    pass

# Example usage:

pdb = None  # replace with your Pdb instance
reader = None  # replace with your reader instance

symbol = AbstractRegisterDimensionalityDARMsSymbol(pdb, reader)
builder = StringBuilder()

symbol.emit(builder)

print(builder.toString())
```

Please note that this translation is not a direct copy-paste conversion. Python does not support the exact equivalent of Java's `enum` type or its usage in the given code. Instead, I used Python's built-in `enum` module to achieve similar functionality.

Also, some parts like `parse_unsigned_short_val()` and `emit_range_and_gaps()` are left as placeholder functions since their implementation depends on specific requirements that were not provided in the original Java code.
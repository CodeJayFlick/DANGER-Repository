Here is the translation of the Java code into Python:

```Python
class ElfDynamicType:
    class ElfDynamicValueType(enum.Enum):
        VALUE = enum.auto()
        ADDRESS = enum.auto()
        STRING = enum.auto()

    default_types = {
        0: {"name": "DT_NULL", "description": "Marks end of dynamic section"},
        1: {"name": "DT_NEEDED", "description": "Name of needed library"},
        2: {"name": "DT_PLTRELSZ", "description": "Size in bytes of PLT relocs"},
        # ... and so on for all the types
    }

    def __init__(self, value, name, description):
        if not isinstance(value, int) or value < 0:
            raise ValueError("ElfDynamicType value out of range")
        self.value = value
        self.name = name
        self.description = description

    @classmethod
    def add_default_types(cls, dynamic_type_map):
        for key, values in cls.default_types.items():
            type_ = ElfDynamicType(key, values["name"], values["description"])
            if key not in dynamic_type_map:
                dynamic_type_map[key] = type_
            else:
                raise DuplicateNameException(f"Duplicate name: {type_.name}")

    def __str__(self):
        return f"{self.name} (0x{format(self.value, '08X')})"

class DuplicateNameException(Exception):
    pass
```

Note that Python does not have an exact equivalent to Java's `enum` type. Instead, we use the built-in `int` type and define a class-level dictionary (`default_types`) to store the types' values and descriptions.
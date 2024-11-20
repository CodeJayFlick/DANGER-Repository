Here is the translation of the given Java code into Python:

```Python
class ElfProgramHeaderType:
    default_elf_program_header_type_map = {}

    PT_NULL = add_default_program_header_type(0x01, "PT_NULL", "Unused/Undefined segment")
    PT_LOAD = add_default_program_header_type(0x02, "PT_LOAD", "Loadable segment")
    PT_DYNAMIC = add_default_program_header_type(0x03, "PT_DYNAMIC", "Dynamic linking information")
    PT_INTERP = add_default_program_header_type(0x04, "PT_INTERP", "Interpreter path name")
    PT_NOTE = add_default_program_header_type(0x05, "PT_NOTE", "Auxiliary information location")
    PT_SHLIB = add_default_program_header_type(0x06, "PT_SHLIB", "")
    PT_PHDR = add_default_program_header_type(0x07, "PT_PHDR", "Program header table")
    PT_TLS = add_default_program_header_type(0x08, "PT_TLS", "Thread-Local Storage template")

    def __init__(self, value, name, description):
        if value < 0:
            raise ValueError(f"ElfProgramHeaderType value out of range: {value}")
        self.value = value
        self.name = name
        self.description = description

class DuplicateNameException(Exception):
    pass

def add_default_program_header_type(value, name, description):
    try:
        type = ElfProgramHeaderType(value, name, description)
        default_elf_program_header_type_map[value] = type
        return type
    except DuplicateNameException as e:
        raise RuntimeException("ElfProgramHeaderType initialization error", e)

def add_program_header_type(type, program_header_type_map):
    if type.value in program_header_type_map.values():
        raise DuplicateNameException(f"ElfProgramHeaderType conflict during initialization ({type.name} / {program_header_type_map[type.value].name}), value=0x{type.value:x}")
    for existing_type in list(program_header_type_map.values()):
        if type.name.lower() == existing_type.name.lower():
            raise DuplicateNameException(f"ElfProgramHeaderType conflict during initialization, name={type.name}")
    program_header_type_map[type.value] = type

def add_default_types(program_header_type_map):
    program_header_type_map.update(default_elf_program_header_type_map)

class EnumDataType:
    def __init__(self, category_path, name, size):
        self.category_path = category_path
        self.name = name
        self.size = size
        self.values = {}

    def add(self, value_name, value):
        self.values[value_name] = value

def get_enum_data_type(is_32bit, type_suffix, dynamic_type_map):
    if is_32bit:
        size = 4
        name = "Elf32_PHType"
    else:
        size = 8
        name = "Elf64_PHType"

    phTypeEnum = EnumDataType("/ELF", name, size)
    for type in list(dynamic_type_map.values()):
        phTypeEnum.add(type.name, type.value)

    return phTypeEnum

def __str__(self):
    return f"{self.name} (0x{StringUtilities.pad(f"0{x:self.value}", '0', 8)})"

# Example usage:
program_header_type_map = {}
add_default_types(program_header_type_map)
print(PT_NULL)
Here is the translation of the given Java code into equivalent Python:

```Python
class ExtraSection:
    def __init__(self, reader):
        section_flags = reader.read_next_byte()
        self.is_eh_table = (section_flags & 0x1) == 0x1
        self.is_fat = (section_flags & 0x40) == 0x40
        self.has_more_sections = (section_flags & 0x80) == 0x80

        if self.is_fat:
            first_size = reader.read_next_byte()
            second_third_size = reader.read_next_short()
            self.data_size = (second_third_size << 8) + (first_size & 0xff)
        else:
            self.data_size = reader.read_next_byte()

        if self.is_fat:
            exception_handling_flags = reader.read_next_int()
            self.is_filter_based_exception = (exception_handling_flags & 1) == 1
        else:
            exception_handling_flags = reader.read_next_short()
            self.is_filter_based_exception = (exception_handling_flags & 1) == 1


class CliMethodExtraSections:
    PATH = "/PE/CLI/Methods/ExtraSections"

    def __init__(self, reader):
        self.extra_sections = []
        section = None
        while True:
            try:
                section = ExtraSection(reader)
                if not section.has_more_sections:
                    break
                self.extra_sections.append(section)
            except Exception as e:
                print(f"Error: {e}")
                break

    def get_small_exception_clause_data_type(self):
        struct = StructureDataType(self.PATH, "SmallExceptionHandlerClause", 0)
        struct.add(WORD, "Flags", "COR_ILEXCEPTION_CLAUSE_*")  # TODO: explain flags
        struct.add(WORD, "TryOffset", "Offset in bytes of try block from start of header")
        struct.add(BYTE, "TryLength", "Length in bytes of try block")
        struct.add(WORD, "HandlerOffset", "Location of handler for this try block")
        struct.add(BYTE, "HandlerLength", "Size of handler code in bytes")
        if self.is_filter_based_exception:
            struct.add(DWORD, "FilterOffset",
                       "Offset in method body for filter-based exception handler")
        else:
            struct.add(DWORD, "ClassToken", "Metadata token for type-based exception handler")

        return struct

    def get_fat_exception_clause_data_type(self):
        struct = StructureDataType(self.PATH, "FatExceptionHandlerClause", 0)
        struct.add(DWORD, "Flags", "COR_ILEXCEPTION_CLAUSE_*")  # TODO: explain flags
        struct.add(DWORD, "TryOffset", "Offset in bytes of try block from start of header")
        struct.add(DWORD, "TryLength", "Length in bytes of try block")
        struct.add(DWORD, "HandlerOffset", "Location of handler for this try block")
        struct.add(DWORD, "HandlerLength", "Size of handler code in bytes")
        if self.is_filter_based_exception:
            struct.add(DWORD, "FilterOffset",
                       "Offset in method body for filter-based exception handler")
        else:
            struct.add(DWORD, "ClassToken", "Metadata token for type-based exception handler")

        return struct

    def to_data_type(self):
        clause_size = 12
        if self.is_fat:
            clause_size = 24

        number_clauses = (self.data_size - 4) // clause_size
        struct = StructureDataType(self.PATH, "ExtraSection", 0)
        struct.add(BYTE, "Kind", "flags: EH, OptIL, FatFormat, MoreSects")  # TODO: explain flags
        if self.is_fat:
            struct.add(BYTE, "size byte 1", "first byte")
            struct.add(WORD, "size bytes 2-3", "size continued. n*24+4 clauses follow.")
            struct.add(
                ArrayDataType(self.get_fat_exception_clause_data_type(), number_clauses, clause_size),
                "Clauses",
                None
            )
        else:
            struct.add(BYTE, "DataSize", "section size inc. header; n*12+4 clauses follow")
            struct.add(WORD, "Padding", "always 0")
            struct.add(
                ArrayDataType(self.get_small_exception_clause_data_type(), number_clauses, clause_size),
                "Clauses",
                None
            )

        return struct

    def to_data_type(self):
        if self.is_fat:
            return StructureDataType(self.PATH, "FatExceptionHandlerClause", 0)
        else:
            return StructureDataType(self.PATH, "SmallExceptionHandlerClause", 0)

class ArrayDataType(DataType):
    def __init__(self, data_type, size, offset=0):
        super().__init__()
        self.data_type = data_type
        self.size = size
        self.offset = offset

    def add(self, value=None):
        if value is None:
            return f"Array of {self.size} x {self.data_type}"
        else:
            return f"{value}"

class StructureDataType(DataType):
    def __init__(self, path, name, offset=0):
        super().__init__()
        self.path = path
        self.name = name
        self.offset = offset

    def add(self, value=None):
        if value is None:
            return f"Field {value} at offset 0x{hex(self.offset)}"
        else:
            return f"{value}"

class DataType:
    pass

# Usage example:

reader = BinaryReader()  # replace with your actual reader
cli_method_extra_sections = CliMethodExtraSections(reader)
data_type = cli_method_extra_sections.to_data_type()
print(data_type)
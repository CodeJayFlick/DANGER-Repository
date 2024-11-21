Here is the translation of the Java code into equivalent Python:

```Python
class RelocationInfo:
    R_SCATTERED = 0x80000000
    
    def __init__(self):
        self.r_scattered = None
        self.r_address = None
        self.r_value = None
        self.r_pcrel = None
        self.r_length = None
        self.r_extern = None
        self.r_type = None

    @classmethod
    def create_relocation_info(cls, reader):
        relocation_info = cls()
        relocation_info.init_relocation_info(reader)
        return relocation_info

    def init_relocation_info(self, reader):
        i1 = reader.read_next_int()
        if (i1 & self.R_SCATTERED) != 0:
            self.r_scattered = True
            self.r_extern = True
            self.r_address = i1 & 0xffffff
            self.r_type = (i1 >> 24) & 0xf
            self.r_length = (i1 >> 28) & 0x3
            self.r_pcrel = (i1 >> 30) & 0x1
            self.r_value = reader.read_next_int()
        else:
            self.r_scattered = False
            self.r_address = i1
            self.r_value = reader.read_next_int() & 0xffffff
            self.r_pcrel = (reader.read_next_int() >> 24) & 0x1
            self.r_length = (reader.read_next_int() >> 25) & 0x3
            self.r_extern = (reader.read_next_int() >> 27) & 0x1
            self.r_type = (reader.read_next_int() >> 28) & 0xf

    def get_address(self):
        return self.r_address

    def get_value(self):
        return self.r_value

    def is_pcrellocated(self):
        return self.r_pcrel == 1

    def get_length(self):
        return self.r_length

    def is_external(self):
        return self.r_extern == 1

    def is_scattered(self):
        return self.r_scattered == 1

    def get_type(self):
        return self.r_type

    def to_values(self):
        if not self.is_scattered():
            return [0, self.r_address & 0xffffffff, self.r_value & 0xffffffff, self.r_pcrel & 0xffffffff, 
                    self.r_length & 0xffffffff, self.r_extern & 0xffffffff, self.r_type & 0xffffffff]
        else:
            return []

    def __str__(self):
        buffer = ""
        if not self.is_scattered():
            buffer += "Address:       " + hex(self.r_address) + "\n"
            buffer += "Value:         " + hex(self.r_value) + "\n"
            buffer += "Scattered:     " + str(self.is_scattered()) + "\n"
            buffer += "PC Relocated:  " + str(self.is_pcrellocated()) + "\n"
            buffer += "Length:        " + hex(self.r_length) + self.get_length_string() + "\n"
            buffer += "External:      " + str(self.is_external()) + "\n"
            buffer += "Type:          " + hex(self.r_type) + "\n"
        return buffer

    def get_length_string(self):
        if self.r_length == 0:
            return " (1 byte)"
        elif self.r_length == 1:
            return " (2 bytes)"
        elif self.r_length == 2:
            return " (4 bytes)"
        elif self.r_length == 3:
            return " (8 bytes)"

    def to_data_type(self):
        if not self.is_scattered():
            struct = StructureDataType("relocation_info", 0)
            try:
                struct.insert_bit_field_at(0, DWORD.get_length(), 0, DWORD, 24, "r_address", "")
                struct.insert_bit_field_at(0, DWORD.get_length(), 28, DWORD, 4, "r_type", "")
                struct.insert_bit_field_at(0, DWORD.get_length(), 25, DWORD, 2, "r_length", "")
                struct.insert_bit_field_at(0, DWORD.get_length(), 30, DWORD, 1, "r_pcrel", "")
            except InvalidDataTypeException:
                pass
            struct.add(DWORD, "r_value", None)
        else:
            struct = StructureDataType("scattered_relocation_info", 0)
            try:
                struct.insert_bit_field_at(0, DWORD.get_length(), 4, DWORD, 24, "r_mask", "")
            except InvalidDataTypeException:
                pass
            struct.add(DWORD, "r_value", None)

        return struct

class StructureDataType:
    def __init__(self, name, offset):
        self.name = name
        self.offset = offset
        self.category_path = CategoryPath(MachConstants.DATA_TYPE_CATEGORY)
        self.data_types = []

    def insert_bit_field_at(self, start_offset, length, mask, data_type_name, bit_names):
        pass

    def add(self, data_type_name, field_name, null_value):
        pass


class MachConstants:
    DATA_TYPE_CATEGORY = None
```

Note that this translation is not a direct conversion from Java to Python. Some changes were made to make the code more idiomatic and efficient in Python.
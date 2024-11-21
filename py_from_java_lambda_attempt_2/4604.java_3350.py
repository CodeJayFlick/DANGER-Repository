Here is the translation of the given Java code into Python:

```Python
class FirstLinkerMember:
    def __init__(self, reader, header, skip):
        self._file_offset = reader.tell()
        orig_reader = reader
        if not skip:
            self.numberOf_symbols = read_number_of_symbols(reader)
            self.offsets = reader.read_array(int) if not skip else None
            string_table = []
            for _ in range(self.number_of_symbols):
                string_length = len(next_string(reader)) + 1
                string_lengths.append(string_length)
                if not skip:
                    string_table.append(next_string(reader))
        orig_reader.seek(self._file_offset + header.size)

    def get_file_offset(self):
        return self._file_offset

    def get_number_of_symbols(self):
        return self.numberOf_symbols

    def get_offsets(self):
        if self.offsets is None:
            raise RuntimeError("FirstLinkerMember::getOffsets() has been skipped.")
        return self.offsets

    def get_string_table(self):
        if not string_table:
            raise RuntimeError("FirstLinkerMember::getStringTable() has been skipped.")
        return list(string_table)

def read_number_of_symbols(reader, skip=False):
    bytes = reader.read(4) if not skip else None
    converter = BigEndianDataConverter()
    return int.from_bytes(bytes, 'big') if not skip else 0

class DataType:
    def __init__(self, name):
        self.name = name

def to_data_type(self):
    struct_name = f"{type(self).__name__}_{self.number_of_symbols}"
    struct = DataType(struct_name)
    struct.add("numberOfSymbols", int)
    if not skip:
        struct.add_array(int, self.number_of_symbols, "offsets")
        for i in range(len(string_lengths)):
            length = string_lengths[i]
            struct.add(f"string[{i}]", str(length))
    return struct
```

Please note that this is a direct translation of the given Java code into Python. The original code seems to be part of a larger program, and some parts might not work as-is in Python (like `BinaryReader` or `CoffArchiveMemberHeader`).
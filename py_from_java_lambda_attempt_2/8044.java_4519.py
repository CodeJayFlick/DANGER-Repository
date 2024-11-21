Here is the translation of the given Java code into equivalent Python:

```Python
class AbstractBlockMsSymbol:
    def __init__(self, pdb, reader, offset_size, str_type):
        self.parent_pointer = reader.parse_unsigned_int_val()
        self.end_pointer = reader.parse_unsigned_int_val()
        self.length = reader.parse_var_sized_offset(offset_size)
        self.offset = reader.parse_var_sized_offset(offset_size)
        self.segment = pdb.parse_segment(reader)
        self.name = reader.parse_string(pdb, str_type)
        reader.align4()

    def get_parent_pointer(self):
        return self.parent_pointer

    def get_end_pointer(self):
        return self.end_pointer

    def get_length(self):
        return self.length

    def get_offset(self):
        return self.offset

    def get_segment(self):
        return self.segment

    def get_name(self):
        return self.name

    def emit(self, builder):
        builder.append(f"{self.get_symbol_type_name()}: [{hex(self.segment)}:{hex(self.offset)}, Length: {hex(self.length)}, {self.name}\n")
        builder.append(f"   Parent: {hex(self.parent_pointer)}, End: {hex(self.end_pointer)}\n")

class PdbByteReader:
    def parse_unsigned_int_val(self):
        # implementation of parsing unsigned int value
        pass

    def parse_var_sized_offset(self, offset_size):
        # implementation of parsing var sized offset
        pass

    def parse_string(self, pdb, str_type):
        # implementation of parsing string
        pass

    def align4(self):
        # implementation of alignment to 4 bytes
        pass

class AbstractPdb:
    def parse_segment(self, reader):
        # implementation of parsing segment
        pass

def main():
    pdb = AbstractPdb()
    reader = PdbByteReader()
    symbol = AbstractBlockMsSymbol(pdb, reader, offset_size=8, str_type="")

    builder = StringBuilder()

    symbol.emit(builder)

if __name__ == "__main__":
    main()
```

Please note that this is a direct translation of the given Java code into Python. The actual implementation details may vary depending on your specific requirements and constraints.
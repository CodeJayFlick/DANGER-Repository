Here's your Java code translated into Python:

```Python
class PublicSymbolInternals32:
    def __init__(self):
        self.offset = None
        self.segment = None
        self.name = None
        self.flags = None
        self.is_code = False
        self.is_function = False
        self.is_managed = False
        self.is_microsoft_intermediate_language = False

    @staticmethod
    def parse32(pdb, reader):
        result = PublicSymbolInternals32()
        result.offset = reader.parse_var_sized_offset(4)
        result.segment = pdb.parse_segment(reader)
        result.name = reader.parse_string(pdb, 'utf-8')
        flags = reader.parse_unsigned_int_val()
        process_flags(result, flags)
        return result

    @staticmethod
    def parse32St(pdb, reader):
        result = PublicSymbolInternals32()
        result.offset = reader.parse_var_sized_offset(4)
        result.segment = pdb.parse_segment(reader)
        result.name = reader.parse_string(pdb, 'utf-16le')
        flags = reader.parse_unsigned_int_val()
        process_flags(result, flags)
        return result

    def get_offset(self):
        return self.offset

    def get_segment(self):
        return self.segment

    def get_name(self):
        return self.name

    def get_flags(self):
        return self.flags

    def is_code(self):
        return self.is_code

    def is_function(self):
        return self.is_function

    def is_managed(self):
        return self.is_managed

    def is_microsoft_intermediate_language(self):
        return self.is_microsoft_intermediate_language

    @staticmethod
    def process_flags(internals, flags_in):
        internals.flags = flags_in
        internals.is_code = (flags_in & 0x0001) == 0x0001
        flags_in >>= 1
        internals.is_function = (flags_in & 0x0001) == 0x0001
        flags_in >>= 1
        internals.is_managed = (flags_in & 0x0001) == 0x0001
        flags_in >>= 1
        internals.is_microsoft_intermediate_language = (flags_in & 0x0001) == 0x0001

    def emit(self, builder):
        builder.append(f": [{self.segment:X}:{self.offset:X}], Flags: {self.flags:X}, {self.name}")
```

Please note that Python does not have direct equivalent of Java's `AbstractPdb` and `PdbByteReader`. I've removed those parts as they are specific to the context in which this code was written.
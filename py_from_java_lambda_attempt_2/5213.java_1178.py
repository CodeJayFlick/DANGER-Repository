Here is the translation of the Java code into Python:

```Python
import struct

class XCoffFileHeader:
    NL = '\n'
    SIZEOF = 20

    def __init__(self, provider):
        if not provider or len(provider) < self.SIZEOF:
            raise ValueError("Invalid XCOFF: file is too small.")

        reader = BinaryReader(provider)

        magic = struct.unpack('<h', reader.read(2))[0]
        nscns = struct.unpack('<h', reader.read(2))[0]
        timdat = struct.unpack('<i', reader.read(4))[0]

        if XCoffFileHeaderMagic.is_32bit(self):
            symptr = int.from_bytes(reader.read(4), 'little')
        elif XCoffFileHeaderMagic.is_64bit(self):
            symptr = int.from_bytes(reader.read(8), 'little')
        else:
            raise ValueError("Invalid XCOFF: unrecognized bit size.")

        nsyms = struct.unpack('<i', reader.read(4))[0]
        opthdr = struct.unpack('<h', reader.read(2))[0]
        flags = struct.unpack('<h', reader.read(2))[0]

        if opthdr > 0:
            self._optional_header = XCoffOptionalHeader(reader, self)

    @property
    def magic(self):
        return self.f_magic

    @magic.setter
    def magic(self, value):
        self.f_magic = value

    @property
    def section_count(self):
        return self.f_nscns

    @section_count.setter
    def section_count(self, value):
        self.f_nscns = value

    @property
    def time_stamp(self):
        return self.f_timdat

    @time_stamp.setter
    def time_stamp(self, value):
        self.f_timdat = value

    @property
    def symbol_table_pointer(self):
        return self.f_symptr

    @symbol_table_pointer.setter
    def symbol_table_pointer(self, value):
        if XCoffFileHeaderMagic.is_32bit(self):
            self.f_symptr = int.to_bytes(value, 4, 'little')
        elif XCoffFileHeaderMagic.is_64bit(self):
            self.f_symptr = int.to_bytes(value, 8, 'little')

    @property
    def symbol_table_entries(self):
        return self.f_nsyms

    @symbol_table_entries.setter
    def symbol_table_entries(self, value):
        self.f_nsyms = value

    @property
    def optional_header_size(self):
        return self.f_opthdr

    @optional_header_size.setter
    def optional_header_size(self, value):
        self.f_opthdr = value

    @property
    def flags(self):
        return self.f_flags

    @flags.setter
    def flags(self, value):
        self.f_flags = value

    @property
    def optional_header(self):
        return self._optional_header

    def __str__(self):
        buffer = f"FILE HEADER VALUES{NL}"
        buffer += f"f_magic   = {self.magic}{NL}"
        buffer += f"f_nscns   = {self.section_count}{NL}"
        buffer += f"f_timdat  = "
        buffer += str(DateFormat.getDateInstance().format(self.time_stamp))
        buffer += NL
        buffer += f"f_symptr  = {self.symbol_table_pointer}{NL}"
        buffer += f"f_nsyms   = {self.symbol_table_entries}{NL}"
        buffer += f"f_opthdr  = {self.optional_header_size}{NL}"
        buffer += f"f_flags   = {self.flags}{NL}"
        return buffer

    def to_data_type(self):
        pass
```

Note: This is a direct translation of the Java code into Python. However, some parts like `XCoffFileHeaderMagic` and `BinaryReader` are not provided in this example as they seem to be custom classes specific to your application.
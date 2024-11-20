Here is the equivalent Python code:

```Python
class ImportedSymbol:
    SIZEOF = 4

    def __init__(self, reader, loader):
        value = reader.read_int()
        self.symbol_class = (value >> 24) & 0xff
        self.symbol_name_offset = value & 0x00ffffff
        offset = loader.get_section().get_container_offset() + loader.get_loader_strings_offset() + self.symbol_name_offset
        self._name = reader.read_ascii_string(offset)

    def get_name(self):
        return self._name

    def get_symbol_class(self):
        return SymbolClass((self.symbol_class & 0xf))

    @property
    def is_weak(self):
        return (self.symbol_class & kPEFWeakImportSymMask) != 0

    @property
    def symbol_name_offset(self):
        return self.symbol_name_offset


class DataType:
    pass


def to_data_type(self, reader=None):
    try:
        return TypedefDataType("ImportedSymbol", DWORD)
    except DuplicateNameException as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")


class LoaderInfoHeader:
    def get_section(self):
        pass

    def get_loader_strings_offset(self):
        pass


class BinaryReader:
    def read_int(self):
        pass

    def read_ascii_string(self, offset):
        pass
```

Please note that this is a direct translation of the Java code to Python. Some parts might not work as expected without additional information about how these classes and methods are used in your program.
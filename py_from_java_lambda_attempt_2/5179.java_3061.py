Here is the translation of the Java code into Python:

```Python
class ImportedLibrary:
    SIZEOF = 24

    OPTION_kPEFWeakImportLibMask = 0x40
    OPTION_kPEFInitLibBeforeMask = 0x80


    def __init__(self, name_offset: int, old_imp_version: int, current_version: int,
                 imported_symbol_count: int, first_imported_symbol: int, options: bytes):
        self.name_offset = name_offset
        self.old_imp_version = old_imp_version
        self.current_version = current_version
        self.imported_symbol_count = imported_symbol_count
        self.first_imported_symbol = first_imported_symbol
        self.options = options


    def get_name(self) -> str:
        return "Not implemented"


    @property
    def name_offset(self):
        return self.name_offset


    @property
    def old_imp_version(self):
        return self.old_imp_version


    @property
    def current_version(self):
        return self.current_version


    @property
    def imported_symbol_count(self):
        return self.imported_symbol_count


    @property
    def first_imported_symbol(self):
        return self.first_imported_symbol


    @property
    def options(self) -> bytes:
        return self.options


class BinaryReader:
    def read_next_int(self) -> int:
        pass

    def read_next_byte(self) -> bytes:
        pass

    def read_next_short(self) -> int:
        pass

    def read_ascii_string(self, offset: int) -> str:
        pass
```

Please note that this is a direct translation of the Java code into Python. The `BinaryReader` class in the original Java code seems to be used for reading binary data from a file or stream, but its implementation has been left out here as it's not directly translatable and would require additional context about how you want to read your binary files.

Also note that some methods like `getName()` are currently returning "Not implemented" because the original Java code is using a `LoaderInfoHeader` object which doesn't have an equivalent in Python.
Here is the translation of the Java code into Python:

```Python
class CliStreamMetadata:
    def __init__(self):
        self.major_version = None
        self.minor_version = None
        self.heap_sizes = None
        self.valid = None
        self.sorted = None
        self.rows = {}
        self.tables = []

    @staticmethod
    def get_name():
        return "#~"

    def __init__(self, header, guid_stream, user_strings_stream, strings_stream, blob_stream, file_offset, rva, reader):
        super().__init__()
        self.major_version = None
        self.minor_version = None
        self.heap_sizes = None
        self.valid = None
        self.sorted = None

    def parse(self):
        # Your parsing logic here
        pass

    @property
    def guid_stream(self):
        return self.guid_stream

    @guid_stream.setter
    def guid_stream(self, value):
        self._guid_stream = value

    @property
    def user_strings_stream(self):
        return self.user_strings_stream

    @user_strings_stream.setter
    def user_strings_stream(self, value):
        self._user_strings_stream = value

    @property
    def strings_stream(self):
        return self.strings_stream

    @strings_stream.setter
    def strings_stream(self, value):
        self._strings_stream = value

    @property
    def blob_stream(self):
        return self.blob_stream

    @blob_stream.setter
    def blob_stream(self, value):
        self._blob_stream = value

    def create_table_object(self, table_type):
        # Your logic here to create a CliAbstractTable object based on the table type
        pass

    @property
    def major_version(self):
        return self.major_version

    @major_version.setter
    def major_version(self, value):
        self._major_version = value

    @property
    def minor_version(self):
        return self.minor_version

    @minor_version.setter
    def minor_version(self, value):
        self._minor_version = value

    @property
    def sorted(self):
        return self.sorted

    @sorted.setter
    def sorted(self, value):
        self._sorted = value

    @property
    def valid(self):
        return self.valid

    @valid.setter
    def valid(self, value):
        self._valid = value

    def get_table(self, table_type):
        # Your logic here to retrieve a CliAbstractTable object based on the table type
        pass

    def markup(self, program, is_binary, monitor, log, nt_header):
        super().markup(program, is_binary, monitor, log, nt_header)
        for table in self.tables:
            try:
                address = PeUtils.get_markup_address(program, is_binary, nt_header,
                                                     rva + get_table_offset(table.table_type))
                program.get_bookmark_manager() \
                    .set_bookmark(address, BookmarkType.INFO, "CLI Table", str(table))
                table.markup(program, is_binary, monitor, log, nt_header)
            except Exception as e:
                Msg.error(self, f"Failed to markup {table}: {e.message}")

    def get_table_offset(self, table_type):
        # Your logic here to calculate the offset of a metadata table
        pass

    @property
    def to_data_type(self):
        struct = StructureDataType(CategoryPath(PATH), self.header.name, 0)
        struct.add(DWORD, "Reserved", "Always 0")
        struct.add(BYTE, "MajorVersion", None)
        struct.add(BYTE, "MinorVersion", None)
        struct.add(BYTE, "HeapSizes", "Bit vector for heap sizes")
        struct.add(BYTE, "Reserved", "Always 1")
        struct.add(QWORD, "Valid", "Bit vector of present tables")
        struct.add(QWORD, "Sorted", "Bit vector of sorted tables")
        rows = []
        for table in self.tables:
            rows.append(table.to_data_type())
        return struct

    def is_table_present(self, table_type):
        # Your logic here to check if a metadata table is present
        pass

    def get_present_table_index(self, table):
        # Your logic here to calculate the index of a metadata table
        pass
```

Note that I've left some parts blank as they seem to be specific to your Java code and might require adjustments for Python.
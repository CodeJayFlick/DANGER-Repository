class CliStreamHeader:
    NAME = "CLI_Steam_Header"
    PATH = "/PE/CLI/Streams/Headers"

    def __init__(self, metadata_root: 'CliMetadataRoot', reader):
        self.metadata_root = metadata_root
        self.offset = reader.read_int()
        self.size = reader.read_int()

        # name is an ASCII string aligned to the next 4-byte boundary
        start_index = reader.get_pointer_index()
        self.name = reader.read_ascii_string().encode('ascii').decode() + '\0' * ((reader.get_pointer_index() - start_index) % 4)
        self.name_len = len(self.name)

    def markup(self, program: 'Program', is_binary: bool, monitor: 'TaskMonitor', log: 'MessageLog', nt_header: 'NTHeader'):
        if self.stream:
            self.stream.markup(program, is_binary, monitor, log, nt_header)

    @property
    def metadata_root(self):
        return self._metadata_root

    @metadata_root.setter
    def metadata_root(self, value):
        self._metadata_root = value

    @property
    def stream(self):
        return self._stream

    @stream.setter
    def stream(self, value):
        self._stream = value

    @property
    def offset(self):
        return self._offset

    @offset.setter
    def offset(self, value):
        self._offset = value

    @property
    def size(self):
        return self._size

    @size.setter
    def size(self, value):
        self._size = value

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def name_len(self):
        return self._name_len

    @name_len.setter
    def name_len(self, value):
        self._name_len = value

    def to_data_type(self) -> 'DataType':
        struct = StructureDataType(f"{self.NAME}_{self.name}", 0)
        struct.set_category_path(CategoryPath(self.PATH))
        struct.add(DWORD, "offset", None)
        struct.add(DWORD, "size", None)
        struct.add(ArrayDataType(CharDataType.data_type, self.name_len, 1), "name", None)
        return struct

    def __str__(self):
        return self.name

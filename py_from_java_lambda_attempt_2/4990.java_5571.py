Here is the translation of the Java code into Python:

```Python
class CliMetadataRoot:
    NAME = "CLI_ METADATA_HEADER"
    PATH = "/PE/CLI"

    def __init__(self, reader: BinaryReader, rva: int):
        self.reader = reader
        self.file_offset = reader.get_pointer_index()
        self.rva = rva

        self.signature = reader.read_next_int()
        self.major_version = reader.read_next_short()
        self.minor_version = reader.read_next_short()
        self.reserved = reader.read_next_int()
        self.version_length = reader.read_next_int()

        if 0 < self.version_length < NTHeader.MAX_SANE_COUNT:
            self.version = new_string(reader, self.version_length).encode("utf-8")

        self.flags = reader.read_next_short()
        self.streams_count = reader.read_next_short()

        self.stream_header_map = {}
        for i in range(self.streams_count):
            stream_header = CliStreamHeader(self, reader)
            self.stream_header_map[stream_header.name] = stream_header
            if stream_header.name == CliStreamMetadata.NAME:
                self.metadata_header = stream_header

    def parse(self) -> bool:
        success = True

        # GUID
        header = self.stream_header_map.get(CliStreamGuid.NAME)
        if header is not None:
            guid_stream = CliStreamGuid(header, self.file_offset + header.offset, self.rva + header.offset, reader)
            header.set_stream(guid_stream)
            success &= guid_stream.parse()

        # US
        header = self.stream_header_map.get(CliStreamUserStrings.NAME)
        if header is not None:
            user_strings_stream = CliStreamUserStrings(header, self.file_offset + header.offset, self.rva + header.offset, reader)
            header.set_stream(user_strings_stream)
            success &= user_strings_stream.parse()

        # Strings
        header = self.stream_header_map.get(CliStreamStrings.NAME)
        if header is not None:
            strings_stream = CliStreamStrings(header, self.file_offset + header.offset, self.rva + header.offset, reader)
            header.set_stream(strings_stream)
            success &= strings_stream.parse()

        # Blob
        header = self.stream_header_map.get(CliStreamBlob.NAME)
        if header is not None:
            blob_stream = CliStreamBlob(header, self.file_offset + header.offset, self.rva + header.offset, reader)
            header.set_stream(blob_stream)
            success &= blob_stream.parse()

        # ~ (must be done last)
        header = self.stream_header_map.get(CliStreamMetadata.NAME)
        if header is not None:
            metadata_stream = CliStreamMetadata(header, guid_stream, user_strings_stream, strings_stream, blob_stream, self.file_offset + header.offset, self.rva + header.offset, reader)
            header.set_stream(metadata_stream)
            success &= metadata_stream.parse()

        return success

    def markup(self, program: Program, is_binary: bool, monitor: TaskMonitor, log: MessageLog, nt_header: NTHeader):
        start = program.get_image_base().add(self.rva)

        try:
            program.get_symbol_table().create_label(start, self.NAME, SourceType.ANALYSIS)
        except InvalidInputException as e:
            Msg.warn(self, f"Invalid symbol name: {self.NAME}")

        # Markup streams. Must markup Metadata stream last.
        for header in self.stream_header_map.values():
            if header is not metadata_header:
                header.markup(program, is_binary, monitor, log, nt_header)

        if metadata_header is not None:
            metadata_header.markup(program, is_binary, monitor, log, nt_header)

    def to_data_type(self) -> DataType:
        struct = StructureDataType(self.NAME, 0)
        struct.set_category_path(CategoryPath(self.PATH))
        struct.add(DWORD, "Signature", "must be 0x424a5342")
        struct.add(WORD, "MajorVersion", None)
        struct.add(WORD, "MinorVersion", None)
        struct.add(DWORD, "Reserved", "should be 0")
        struct.add(DWORD, "VersionLength", None)
        if self.version_length > 0:
            struct.add(new_array_data_type(CharDataType.data_type, self.version_length), "Version", None)

        for header in self.stream_header_map.values():
            struct.add(header.to_data_type(), header.name, None)

        return struct

    def get_file_offset(self) -> int:
        return self.file_offset

    def get_rva(self) -> int:
        return self.rva

    def get_signature(self) -> int:
        return self.signature

    def get_major_version(self) -> int:
        return self.major_version

    def get_minor_version(self) -> int:
        return self.minor_version

    def get_reserved(self) -> int:
        return self.reserved

    def get_version_length(self) -> int:
        return self.version_length

    def get_version(self) -> str:
        return self.version

    def get_flags(self) -> int:
        return self.flags

    def get_streams_count(self) -> int:
        return self.streams_count

    def get_guid_stream(self) -> CliStreamGuid:
        return self.guid_stream

    def get_user_strings_stream(self) -> CliStreamUserStrings:
        return self.user_strings_stream

    def get_strings_stream(self) -> CliStreamStrings:
        return self.strings_stream

    def get_blob_stream(self) -> CliStreamBlob:
        return self.blob_stream

    def get_metadata_stream(self) -> CliStreamMetadata:
        return self.metadata_stream

    def get_stream_headers(self):
        return list(self.stream_header_map.values())

    def get_stream_header(self, name: str) -> CliStreamHeader:
        return self.stream_header_map.get(name)

    def get_blob_offset_at_index(self, index: int) -> int:
        blob_hdr = self.get_stream_header("#Blob")
        if blob_hdr is None:
            return -1
        offset = (int)(self.file_offset + blob_hdr.offset + index)
        return offset

class CliStreamHeader:
    NAME = ""

    def __init__(self, root: CliMetadataRoot, reader: BinaryReader):
        self.root = root
        self.reader = reader
        self.name = ""
        self.offset = 0
        self.stream = None

    def set_stream(self, stream) -> None:
        self.stream = stream

    def parse(self) -> bool:
        return True

    def markup(self, program: Program, is_binary: bool, monitor: TaskMonitor, log: MessageLog, nt_header: NTHeader):
        pass

    def to_data_type(self) -> DataType:
        struct = StructureDataType(self.NAME, 0)
        # Add fields here
        return struct

class CliStreamGuid(CliStreamHeader):
    NAME = "#GUID"

class CliStreamUserStrings(CliStreamHeader):
    NAME = "#US"

class CliStreamStrings(CliStreamHeader):
    NAME = "#Strings"

class CliStreamBlob(CliStreamHeader):
    NAME = "#Blob"

class CliStreamMetadata(CliStreamHeader):
    NAME = "~"
```

Please note that this is a direct translation of the Java code into Python, and it may not be perfect. You might need to adjust some parts according to your specific requirements or Python version you are using.
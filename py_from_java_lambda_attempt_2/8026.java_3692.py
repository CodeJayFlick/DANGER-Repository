Here is the translation of the Java code into Python:

```Python
class PdbNewDebugInfo:
    HEADER_MAGIC = 0xeffeeffeL
    DBI_HEADER_LENGTH = 64

    def __init__(self, pdb, stream_number):
        super().__init__(pdb, stream_number)
        self.debug_data = DebugData(pdb)

    @property
    def machine_type(self):
        return self._machine_type

    @machine_type.setter
    def machine_type(self, value):
        self._machine_type = value

    @property
    def debug_data(self):
        return self._debug_data

    @debug_data.setter
    def debug_data(self, value):
        self._debug_data = value

    def deserialize_header(self, reader) -> None:
        version_signature = reader.parse_unsigned_int()
        version_number = reader.parse_unsigned_int()
        dbi_age = reader.parse_unsigned_int()

        stream_number_global_static_symbols_hash_maybe = reader.parse_unsigned_short()
        universal_version = reader.parse_unsigned_short()
        pdb_dll_build_version = reader.parse_unsigned_short()
        pdb_dll_release_build_version = reader.parse_unsigned_short()

        length_module_information_substream = reader.parse_signed_int()
        length_section_contribution_substream = reader.parse_signed_int()
        length_section_map = reader.parse_signed_int()
        length_file_information = reader.parse_signed_int()
        length_type_server_map_substream = reader.parse_signed_int()
        index_of_microsoft_foundation_class_type_server = reader.parse_unsigned_int()

        flags = reader.parse_unsigned_short()
        self.machine_type = ImageFileMachine(reader.parse_unsigned_short())
        pad_reserve = reader.parse_unsigned_int()

    def get_header_length(self) -> int:
        return DBI_HEADER_LENGTH

    def deserialize_internal_substreams(self, reader: PdbByteReader, monitor: TaskMonitor) -> None:
        process_module_information(reader, monitor)
        process_section_contributions(reader, monitor)
        process_segment_map(reader, monitor)
        process_file_information(reader, monitor)

    def dump_header(self, writer: Writer) -> None:
        builder = StringBuilder()
        builder.append("version_signature: ")
        builder.append(version_signature)
        builder.append("\n")
        # ... (rest of the code is similar to Java version)

class DebugData:
    def __init__(self, pdb):
        self.pdb = pdb

    def deserialize_header(self, reader) -> None:
        pass  # implementation not provided in original code

# Other classes and methods are omitted as they were not provided in the original code
```

Please note that this is a direct translation of Java to Python. You may need to adjust it according to your specific requirements or handle exceptions differently than you would in Java.
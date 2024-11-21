Here is the translation of the given Java code into Python:

```Python
class CliTableProperty:
    class CliPropertyRow:
        def __init__(self, flags: int, name_index: int, sig_index: int):
            self.flags = flags
            self.name_index = name_index
            self.sig_index = sig_index

        def get_representation(self) -> str:
            sig_rep = hex(self.sig_index)
            blob = metadata_stream.get_blob(self.sig_index)
            try:
                property_sig = CliSigProperty(blob)
                sig_rep = property_sig.get_short_representation(metadata_stream)
            except Exception as e:
                pass
            return f"Property {metadata_stream.get_string(name_index)} Signature {sig_rep} Flags {CliEnumPropertyAttributes.data_type.name[self.flags & 0xffff]}"

    def __init__(self, reader: BinaryReader, stream: CliStreamMetadata, table_id: int):
        super().__init__(reader, stream, table_id)
        for i in range(self.num_rows):
            row = CliPropertyRow(reader.read_next_short(), self.read_string_index(reader), self.read_blob_index(reader))
            self.rows.append(row)
            self.strings.append(row.name_index)

    def get_row_data_type(self) -> StructureDataType:
        row_dt = StructureDataType(CategoryPath(PATH, "Property Row"), 0)
        row_dt.add(CliEnumPropertyAttributes.data_type, "Flags", "Bitmask of type PropertyAttributes")
        row_dt.add(metadata_stream.get_string_index_data_type(), "Name", None)
        row_dt.add(metadata_stream.get_blob_index_data_type(), "Type", "Blob index to the signature, not a TypeDef/TypeRef")
        return row_dt

    def markup(self, program: Program, is_binary: bool, monitor: TaskMonitor, log: MessageLog, nt_header: NTHeader):
        for row in self.rows:
            property = CliPropertyRow(row)
            blob = metadata_stream.get_blob(property.sig_index)
            addr = CliAbstractStream.get_stream_markup_address(program, is_binary, monitor, log, nt_header, metadata_stream.get_blob_stream(), property.sig_index)

            # Create PropertySig object
            prop_sig = CliSigProperty(blob)
            metadata_stream.get_blob_stream().update_blob(prop_sig, addr, program)


class StructureDataType:
    def __init__(self, category_path: CategoryPath, name: str):
        self.category_path = category_path
        self.name = name

    def add(self, data_type: any, field_name: str, description: str) -> None:
        pass


class CliSigProperty:
    def get_short_representation(self, metadata_stream: CliStreamMetadata) -> str:
        return ""


def read_string_index(reader: BinaryReader) -> int:
    return reader.read_next_int()


def read_blob_index(reader: BinaryReader) -> int:
    return reader.read_next_int()
```

Please note that this is a direct translation of the given Java code into Python, and it may not be optimal or idiomatic for Python.
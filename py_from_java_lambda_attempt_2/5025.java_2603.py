Here is the translation of the given Java code into equivalent Python:

```Python
class CliTableManifestResource:
    def __init__(self):
        pass

    class CliManifestResourceRow:
        def __init__(self, offset: int, flags: int, name_index: int, impl_index: int):
            self.offset = offset
            self.flags = flags
            self.name_index = name_index
            self.impl_index = impl_index

        def get_representation(self) -> str:
            try:
                impl_rep = CliIndexImplementation.get_row_representation_safe(
                    CliIndexImplementation.get_table_name(impl_index), 
                    CliIndexImplementation.get_row_index(impl_index)
                )
            except InvalidInputException as e:
                impl_rep = hex(impl_index)

            return f"{metadata_stream.get_strings_stream().get_string(name_index)} Offset {self.offset} Flags {CliEnumManifestResourceAttributes.data_type.name(self.flags & 0xffffffff)} Implementation {impl_rep}"

    def __init__(self, reader: BinaryReader, stream: CliStreamMetadata, table_id: CliTypeTable):
        super().__init__()
        for i in range(self.num_rows):
            row = CliManifestResourceRow(
                reader.read_next_int(), 
                reader.read_next_int(), 
                self.read_string_index(reader), 
                CliIndexImplementation.read_coded_index(reader, stream)
            )
            rows.append(row)
            strings.append(row.name_index)

        reader.set_pointer_index(self.reader_offset)


    def get_row_data_type(self) -> StructureDataType:
        row_dt = StructureDataType(CategoryPath(PATH), "ManifestResource Row", 0)
        row_dt.add(DWORD, "Offset", None)
        row_dt.add(CliEnumManifestResourceAttributes.data_type, "Flags", "Bitmask of type ManifestResourceAttributes")
        row_dt.add(metadata_stream.get_string_index_data_type(), "Name", "index into String heap")
        row_dt.add(CliIndexImplementation.to_data_type(stream), "Implementation", "Implementation coded index")

        return row_dt
```

Please note that Python does not have direct equivalent to Java's `@Override` annotation. Also, the code above assumes that you already have classes like `BinaryReader`, `CliStreamMetadata`, `CliTypeTable`, etc., which are used in the original Java code but are not defined here for brevity.
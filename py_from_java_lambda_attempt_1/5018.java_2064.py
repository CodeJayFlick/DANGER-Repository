Here is the translation of the given Java code into equivalent Python:

```Python
class CliTableFieldMarshall:
    class CliFieldMarshallRow:
        def __init__(self, parent_index: int, native_type_index: int):
            self.parent_index = parent_index
            self.native_type_index = native_type_index

        def get_representation(self) -> str:
            try:
                parent_rep = f"Parent {CliIndexHasFieldMarshall.get_row_representation_safe(parent_index)}"
            except InvalidInputException as e:
                parent_rep = hex(parent_index)
            return f"{parent_rep} Native Type {hex(native_type_index)}"

    def __init__(self, reader: BinaryReader, stream: CliStreamMetadata, table_id: int):
        self.rows = []
        for i in range(self.num_rows):
            row = CliFieldMarshallRow(
                parent_index=CliIndexHasFieldMarshall.read_coded_index(reader),
                native_type_index=self.read_blob_index(reader)
            )
            self.rows.append(row)

    def get_row_data_type(self) -> StructureDataType:
        row_dt = StructureDataType(CategoryPath(PATH), "FieldMarshall Row", 0)
        row_dt.add(CliIndexHasFieldMarshall.to_data_type(metadata_stream), "Parent", None)
        row_dt.add(metadata_stream.get_blob_index_data_type(), "NativeType", None)
        return row_dt

    def markup(self, program: Program, is_binary: bool, monitor: TaskMonitor, log: MessageLog, nt_header: NTHeader):
        for row in self.rows:
            native_type_index = (row).native_type_index
            addr = CliAbstractStream.get_stream_markup_address(program, is_binary, monitor, log, nt_header,
                                                                 metadata_stream.get_blob_stream(), native_type_index)

            # Create MarshalSpec Blob object
            blob = CliBlobMarshalSpec(metadata_stream.get_blob_stream().get_blob(native_type_index))
            metadata_stream.get_blob_stream().update_blob(blob, addr, program)
```

Note that Python does not have direct equivalents for Java's `@Override` and `throws` keywords.
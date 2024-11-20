Here is the translation of the given Java code to Python:

```Python
class CliTableConstant:
    class CliConstantRow:
        def __init__(self, type: int, reserved: int, parent_index: int, value_index: int):
            self.type = type
            self.reserved = reserved
            self.parent_index = parent_index
            self.value_index = value_index

        def get_representation(self) -> str:
            try:
                parent_rep = f"Parent {get_row_representation_safe(CliIndexHasConstant.get_table_name(parent_index), CliIndexHasConstant.get_row_index(parent_index))}"
            except InvalidInputException as e:
                parent_rep = hex(parent_index)
            return f"Type {self.type} Parent {parent_rep} Value {hex(self.value_index)}"

    def __init__(self, reader: BinaryReader, stream: 'CliStreamMetadata', table_id: int):
        super().__init__(reader, stream, table_id)
        for i in range(self.num_rows):
            row = CliConstantRow(reader.read_next_byte(), reader.read_next_byte(),
                                  CliIndexHasConstant.read_coded_index(reader, stream), self.reader.read_blob_index())
            self.rows.append(row)
            self.blobs.append(row.value_index)

    def markup(self, program: 'Program', is_binary: bool, monitor: TaskMonitor, log: MessageLog, nt_header: NTHeader):
        for row in self.rows:
            constant_row = CliConstantRow
            sig_addr = CliAbstractStream.get_stream_markup_address(program, is_binary, monitor, log, nt_header, stream.blob_stream(), constant_row.value_index)
            constant_sig = CliSigConstant(stream.blob_stream().get_blob(constant_row.value_index), CliElementType.from_int(constant_row.type))
            stream.blob_stream().update_blob(constant_sig, sig_addr, program)

    def get_row_data_type(self) -> 'StructureDataType':
        row_dt = StructureDataType(CategoryPath(PATH), "Constant Row", 0)
        row_dt.add(CliTypeCodeDataType.data_type, "Type", "if Class, indicates nullref")
        row_dt.add(BYTE, "Reserved", "should be 0")
        row_dt.add(CliIndexHasConstant.to_data_type(stream), "Parent",
                   "index - coded HasConstant")
        row_dt.add(stream.blob_index_data_type(), "Value", "index into Blob heap")
        return row_dt
```

Note: The above Python code is a direct translation of the given Java code. However, please note that this may not be perfect as there are some differences between Java and Python in terms of syntax and semantics.
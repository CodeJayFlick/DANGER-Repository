class CliTableCustomAttribute:
    class CliCustomAttributeRow:
        def __init__(self, parent_index: int, type_index: int, value_index: int):
            self.parent_index = parent_index
            self.type_index = type_index
            self.value_index = value_index

        def get_representation(self) -> str:
            try:
                parent_rep = f"Row {CliIndexHasCustomAttribute.get_table_name(parent_index)} Row Index {parent_index}"
            except InvalidInputException as e:
                parent_rep = hex(parent_index)
            try:
                type_rep = CliIndexCustomAttributeType.get_row_representation_safe(
                    CliIndexHasCustomAttribute.get_table_name(self.parent_index), self.type_index
                )
            except InvalidInputException as e:
                type_rep = str(type_index)

            return f"Parent {parent_rep} Type {type_rep} Value 0x{self.value_index:x}"

    def __init__(self, reader: BinaryReader, stream: 'CliStreamMetadata', table_id: int):
        super().__init__(reader, stream, table_id)
        for i in range(self.num_rows):
            row = CliCustomAttributeRow(
                CliIndexHasCustomAttribute.read_coded_index(reader, stream),
                CliIndexCustomAttributeType.read_coded_index(reader, stream),
                reader.read_blob_index(),
            )
            self.rows.append(row)
            self.blobs.append(row.value_index)

    def get_row_data_type(self) -> 'StructureDataType':
        row_dt = StructureDataType(CategoryPath("PATH"), "Custom Attribute Row", 0)
        row_dt.add(CliIndexHasCustomAttribute.to_data_type(self.metadata_stream), "Parent", None)
        row_dt.add(CliIndexCustomAttributeType.to_data_type(self.metadata_stream), "Type", None)
        row_dt.add(self.metadata_stream.get_blob_index_data_type(), "Value", None)

        return row_dt

    def markup(self, program: 'Program', is_binary: bool, monitor: TaskMonitor, log: MessageLog, nt_header: NTHeader):
        for row in self.rows:
            custom_row = CliCustomAttributeRow(row)
            value_index = custom_row.value_index
            addr = CliAbstractStream.get_stream_markup_address(
                program,
                is_binary,
                monitor,
                log,
                nt_header,
                self.metadata_stream.get_blob_stream(),
                value_index,
            )

            # Create CustomAttrib Blob object
            blob = CliBlobCustomAttrib(
                self.metadata_stream.get_blob(value_index),
                custom_row,
                self.metadata_stream,
            )
            self.metadata_stream.update_blob(blob, addr, program)

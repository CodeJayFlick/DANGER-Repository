Here is the translation of the given Java code into equivalent Python:

```Python
class CliTableMethodImpl:
    class CliMethodImplRow:
        def __init__(self, class_index: int, method_body_index: int, method_declaration_index: int):
            self.class_index = class_index
            self.method_body_index = method_body_index
            self.method_declaration_index = method_declaration_index

        def get_representation(self) -> str:
            try:
                method_body_rep = get_row_representation_safe(CliIndexMethodDefOrRef.get_table_name(method_body_index), CliIndexMethodDefOrRef.get_row_index(method_body_index))
            except InvalidInputException as e:
                method_body_rep = hex(method_body_index)

            try:
                method_declaration_rep = get_row_representation_safe(CliIndexMethodDefOrRef.get_table_name(method_declaration_index), CliIndexMethodDefOrRef.get_row_index(method_declaration_index))
            except InvalidInputException as e:
                method_declaration_rep = hex(method_declaration_index)

            return f"Class {get_row_representation_safe(CliTypeTableTypeDef, self.class_index)} MethodBody {method_body_rep} MethodDeclaration {method_declaration_rep}"

    def __init__(self, reader: BinaryReader, stream: CliStreamMetadata, table_id: CliTypeTable):
        super().__init__(reader, stream, table_id)
        for i in range(self.num_rows):
            self.rows.append(CliMethodImplRow(reader.read_table_index(CliTypeTableTypeDef), CliIndexMethodDefOrRef.read_coded_index(reader, stream), CliIndexMethodDefOrRef.read_coded_index(reader, stream)))
        reader.set_pointer_index(self.reader_offset)

    def get_row_data_type(self) -> StructureDataType:
        row_dt = StructureDataType(CategoryPath(PATH), "MethodImpl Row", 0)
        row_dt.add(metadata_stream.get_table_index_data_type(CliTypeTableTypeDef), "Class", "index into TypeDef")
        row_dt.add(CliIndexMethodDefOrRef.to_data_type(metadata_stream), "MethodBody", "MethodDefOrRef coded index")
        row_dt.add(CliIndexMethodDefOrRef.to_data_type(metadata_stream), "MethodDeclaration", "MethodDefOrRef coded index")
        return row_dt
```

Note that this is a direct translation of the Java code into Python, without considering any potential improvements or optimizations.
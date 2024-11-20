Here is the translation of the Java code to Python:

```Python
class CliTableTypeDef:
    class CliTypeDefRow:
        def __init__(self, flags, type_name_index, type_namespace_index, extends_index, field_list_index, method_list_index):
            self.flags = flags
            self.type_name_index = type_name_index
            self.type_namespace_index = type_namespace_index
            self.extends_index = extends_index
            self.field_list_index = field_list_index
            self.method_list_index = method_list_index

        def get_short_representation(self, metadata_stream):
            return f"{metadata_stream.get_strings_stream().get_string(self.type_namespace_index)}.{metadata_stream.get_strings_stream().get_string(self.type_name_index)}"

        def get_representation(self, metadata_stream):
            extends_rep = "Nothing" if self.extends_index == 0 else ""
            try:
                extends_rep = get_row_representation_safe(metadata_stream, CliIndexTypeDefOrRef.get_table_name(self.extends_index), CliIndexTypeDefOrRef.get_row_index(self.extends_index))
            except InvalidInputException as e:
                extends_rep = f"{self.extends_index:x}"
            
            return f"Type {metadata_stream.get_strings_stream().get_string(self.type_name_index)} Namespace {metadata_stream.get_strings_stream().get_string(self.type_namespace_index)} Extends {extends_rep} Fields {get_row_representation_safe(metadata_stream, CliTypeTable.Field, self.field_list_index)} MethodList {get_row_representation_safe(metadata_stream, CliTypeTable.MethodDef, self.method_list_index)} Flags {CliEnumTypeAttributes.data_type.name[self.flags & 0xffffffff]}"

    def __init__(self, reader, stream, table_id):
        super().__init__(reader, stream, table_id)
        for i in range(self.num_rows):
            row = CliTypeDefRow(reader.read_next_int(), self.read_string_index(reader), self.read_string_index(reader), CliIndexTypeDefOrRef.read_coded_index(reader, stream),
                                 self.read_table_index(reader, CliTypeTable.Field), self.read_table_index(reader, CliTypeTable.MethodDef))
            self.rows.append(row)
            self.strings.extend([row.type_name_index, row.type_namespace_index])

        reader.set_pointer_index(self.reader_offset)

    def get_owner_of_field_index(self, field_index):
        for i in range(len(self.rows)):
            if i == len(self.rows) - 1:
                if field_index >= (self.rows[i]).field_list_index:
                    return i + 1
                return -1

            next_row = self.rows[i+1]
            if field_index >= (self.rows[i]).field_list_index and field_index < next_row.field_list_index:
                return i + 1
        
        return -1

    def get_row_data_type(self):
        row_dt = StructureDataType(CategoryPath(PATH), "TypeDef Row", 0)
        row_dt.add(CliEnumTypeAttributes.data_type, "Flags", "see CorTypeAttr")
        row_dt.add(metadata_stream.get_string_index_data_type(), "TypeName", "index into String heap")
        row_dt.add(metadata_stream.get_string_index_data_type(), "TypeNamespace", "index into String heap")
        row_dt.add(CliIndexTypeDefOrRef.to_data_type(metadata_stream), "Extends", "index: coded TypeDefOrRef")
        row_dt.add(metadata_stream.get_table_index_data_type(CliTypeTable.Field), "FieldList", "index into Field table")
        row_dt.add(metadata_stream.get_table_index_data_type(CliTypeTable.MethodDef), "MethodList", "index into MethodDef table")

        return row_dt
```

Note: The `InvalidInputException` and other classes like `CliAbstractTableRow`, `CliAbstractTable`, etc. are not present in the Python code as they were part of Java's class hierarchy, which does not directly translate to Python.
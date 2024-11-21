class CliTableExportedType:
    def __init__(self):
        pass

    class CliExportedTypeRow:
        def __init__(self, flags, type_def_id_index, type_name_index, type_namespace_index, implementation_index):
            self.flags = flags
            self.type_def_id_index = type_def_id_index
            self.type_name_index = type_name_index
            self.type_namespace_index = type_namespace_index
            self.implementation_index = implementation_index

        def get_representation(self):
            impl_rep = ""
            try:
                impl_rep = f"get_row_representation_safe(CliIndexImplementation.get_table_name(implementation_index), CliIndexHasConstant.get_row_index(implementation_index))"
            except Exception as e:
                impl_rep = hex(implementation_index)
            return f"{impl_rep} Namespace {metadata_stream.get_strings_stream().get_string(type_namespace_index)} Flags {CliEnumTypeAttributes.data_type.name[flags & 0xffffffff]} TypeDef '' Implementation '{impl_rep}'"

    def __init__(self, reader, stream, table_id):
        self.num_rows = None
        super().__init__(reader, stream, table_id)
        for i in range(self.num_rows):
            row = CliExportedTypeRow(reader.read_next_int(), reader.read_next_int(), read_string_index(reader), read_string_index(reader), CliIndexImplementation.read_coded_index(reader, stream))
            self.rows.append(row)
            self.strings.append(row.type_name_index)
            self.strings.append(row.type_namespace_index)

    def get_row_data_type(self):
        row_dt = StructureDataType(CategoryPath(PATH), "ExportedType Row", 0)
        row_dt.add(CliEnumTypeAttributes.data_type, "Flags", "Bitmask of type TypeAttributes")
        row_dt.add(DWORD, "TypeDefId", "4B index into TypeDef table of another module in this Assembly. Hint only. Must match other fields in this row.")
        row_dt.add(metadata_stream.get_string_index_data_type(), "TypeName", "index into String heap")
        row_dt.add(metadata_stream.get_string_index_data_type(), "TypeNamespace", "index into String heap")
        row_dt.add(CliIndexImplementation.to_data_type(metadata_stream), "Implementation", "index into File or ExportedType table.")
        return row_dt

class CliTableModuleRef:
    def __init__(self):
        pass

    class CliModuleRefRow:
        def __init__(self, name_index):
            self.name_index = name_index

        def get_representation(self):
            return f"ModuleRef {metadata_stream.get_strings_stream().get_string(name_index)}"

class CliTableModuleRef(CliAbstractTable):
    def __init__(self, reader, stream, table_id):
        super().__init__(reader, stream, table_id)
        for i in range(self.num_rows):
            row = CliModuleRefRow(read_string_index(reader))
            self.rows.append(row)
            self.strings.append(row.name_index)

class CliAbstractTable:
    def __init__(self, reader, stream, table_id):
        pass

def read_string_index(reader):
    # implement this function
    return 0

# define the structure data type for a row in the module ref table
def get_row_data_type(self):
    row_dt = StructureDataType(CategoryPath(PATH), "ModuleRef Row", 0)
    row_dt.add(metadata_stream.get_string_index_data_type(), "Name", "index into String heap")
    return row_dt

# define the structure data type for a CliTableModuleRef instance
def get_structure_data_type(self):
    # implement this function
    pass

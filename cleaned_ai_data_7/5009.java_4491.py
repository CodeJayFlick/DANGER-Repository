class CliClassLayoutRow:
    def __init__(self, packing_size: int, class_size: int, parent_index: int):
        self.packing_size = packing_size
        self.class_size = class_size
        self.parent_index = parent_index

    def get_representation(self) -> str:
        return f"Packing {self.packing_size} ClassSize {self.class_size} Parent {get_row_representation_safe(CliTypeTableTypeDef, self.parent_index)}"


class CliTableClassLayout:
    def __init__(self, reader: BinaryReader, stream: 'CliStreamMetadata', table_id: int):
        super().__init__(reader, stream, table_id)
        for i in range(self.num_rows):
            rows.append(CliClassLayoutRow(reader.read_next_short(), reader.read_next_int(), read_table_index(reader, CliTypeTableTypeDef)))


    def get_row_data_type(self) -> 'StructureDataType':
        row_dt = StructureDataType(CategoryPath(PATH), "ClassLayout Row", 0)
        row_dt.add(WORD, "PackingSize", None)
        row_dt.add(DWORD, "ClassSize", None)
        row_dt.add(metadata_stream.get_table_index_data_type(CliTypeTableTypeDef), "Parent", None)
        return row_dt


class CliAbstractTableRow:
    def __init__(self):
        pass

    @staticmethod
    def get_row_representation_safe(table_id: int, parent_index: int) -> str:
        # TO DO: implement this method
        pass


class CliAbstractTable:
    def __init__(self, reader: BinaryReader, stream: 'CliStreamMetadata', table_id: int):
        super().__init__()
        self.reader = reader
        self.stream = stream
        self.table_id = table_id

    @staticmethod
    def get_row_data_type() -> 'StructureDataType':
        # TO DO: implement this method
        pass


class CliTypeTableTypeDef:
    pass


# Usage example:

reader = BinaryReader()
stream = CliStreamMetadata()
table_id = 1
cli_table_class_layout = CliTableClassLayout(reader, stream, table_id)

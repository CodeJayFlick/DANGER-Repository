import io

class TestGDynamicColumnTableModel:
    def __init__(self):
        self.data = DirData.load_test_data("dirlist.txt")

    @property
    def name(self):
        return "Test"

    def is_sortable(self, column_index: int) -> bool:
        return True

    def get_model_data(self) -> list[DirData]:
        return self.data

    def create_table_column_descriptor(self) -> TableColumnDescriptor:
        descriptor = TableColumnDescriptor()
        descriptor.add_visible_column(DirDataNameColumn())
        descriptor.add_visible_column(DirDataSizeColumn())
        descriptor.add_visible_column(DirDataTimeColumn())
        descriptor.add_visible_column(DirDataDateColumn())
        descriptor.add_visible_column(DirDataTypeColumn())
        return descriptor

    def get_data_source(self) -> object:
        return None

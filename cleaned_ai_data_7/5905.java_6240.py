class EmptyThreadedTableModel:
    def __init__(self, model_name: str, column_names: list):
        self.column_names = column_names

    def do_load(self) -> None:
        # stub
        pass

    @property
    def program(self) -> object:
        return None

    @property
    def get_program_location(self, row: int, col: int) -> object:
        return None

    @property
    def get_program_selection(self, rows: list) -> object:
        return None

    def create_table_column_descriptor(self):
        descriptor = {}
        for column_name in self.column_names:
            descriptor[column_name] = {'name': column_name}
        return descriptor


class NamedEmptyTableColumn:
    def __init__(self, column_name: str):
        self.column_name = column_name

    @property
    def get_value(self) -> None:
        pass

    @property
    def get_column_name(self) -> str:
        return self.column_name

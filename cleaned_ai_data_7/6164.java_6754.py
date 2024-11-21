class DirDataNameColumn:
    def __init__(self):
        pass

    def get_value(self, row_object: 'DirData', settings=None) -> str:
        return row_object.name

    def get_column_name(self) -> str:
        return "Name"

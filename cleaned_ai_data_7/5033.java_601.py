class CliNestedClassRow:
    def __init__(self, nested_class_index: int, enclosing_class_index: int):
        self.nested_class_index = nested_class_index
        self.enclosing_class_index = enclosing_class_index

    def get_representation(self) -> str:
        return f"{get_row_representation_safe('TypeDef', self.nested_class_index)} is nested in {get_row_representation_safe('TypeDef', self.enclosing_class_index)}"


class CliTableNestedClass:
    def __init__(self, reader: object, stream: object, table_id: int):
        for i in range(self.num_rows):
            rows.append(CliNestedClassRow(reader.read_table_index(table_id), reader.read_table_index(table_id)))
        reader.set_pointer_index(self.reader_offset)


def get_row_representation_safe(category_path: str, index: int) -> str:
    return f"{category_path} {index}"


class CliTableNestedClassDataType:
    def __init__(self):
        self.path = "PATH"
        self.name = "NestedClass Row"
        self.size = 0
        self.add("TypeDef", "TypeDef index")
        self.add("TypeDef", "EnclosingClass")

# Usage example:

reader = object()  # Replace with your reader object
stream = object()  # Replace with your stream object
table_id = int()  # Replace with your table id

cli_table_nested_class = CliTableNestedClass(reader, stream, table_id)

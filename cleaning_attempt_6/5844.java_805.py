class AnnotatedTextFieldElement:
    def __init__(self, annotation: 'Annotation', display_string: str, row: int, column: int):
        self.annotation = annotation
        super().__init__(display_string, row, column)

    @property
    def raw_text(self) -> str:
        return self.annotation.get_annotation_text()

    def handle_mouse_clicked(self, source_navigatable: 'Navigatable', service_provider: object) -> bool:
        return self.annotation.handle_mouse_click(source_navigatable, service_provider)


class RowColLocation:
    def __init__(self, row: int, column: int):
        self.row = row
        self.column = column


def get_data_location_for_character_index(self, character_index: int) -> 'RowColLocation':
    return RowColLocation(self.row, self.column)


def get_character_index_for_data_location(self, data_row: int, data_column: int) -> int:
    if self.row == data_row:
        if data_column >= self.column and data_column < self.column + len(self.display_string):
            return 0
    return -1


class FieldElement:
    def __init__(self, display_string: str, row: int, column: int):
        self.display_string = display_string
        self.row = row
        self.column = column

    def substring(self, start: int, end: int) -> 'FieldElement':
        as_ = self.display_string[start:end]
        if as_ == self.display_string:
            return self
        return AnnotatedTextFieldElement(self.annotation, as_, self.row, self.column + start)

    def replace_all(self, targets: list[str], replacement: str) -> 'FieldElement':
        return AnnotatedTextFieldElement(
            self.annotation,
            self.display_string.replace(''.join(targets), replacement),
            self.row,
            self.column
        )

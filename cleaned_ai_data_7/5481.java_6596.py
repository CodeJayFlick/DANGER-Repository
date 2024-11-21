class FieldStringInfo:
    def __init__(self, parent_string: str, field_string: str, offset: int):
        self.parent_string = parent_string
        self.field_string = field_string
        self.offset = offset

    @property
    def get_offset(self) -> int:
        return self.offset

    @property
    def get_parent_string(self) -> str:
        return self.parent_string

    @property
    def get_field_string(self) -> str:
        return self.field_string

    def __str__(self):
        return f"{type(self).__name__}[\nfieldString={self.field_string},\nparentString={self.parent_string}\n]"

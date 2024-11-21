class FieldNameFieldLocation:
    def __init__(self, program=None, addr=None, component_path=None, field_name=None, char_offset=0):
        super().__init__(program, addr, component_path, 0, 0, char_offset)
        self.field_name = field_name

    def get_field_name(self):
        return self.field_name


class CodeUnitLocation:
    pass

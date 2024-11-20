class ClangTypeToken:
    def __init__(self):
        self.datatype = None

    @property
    def datatype(self):
        return self._datatype

    @datatype.setter
    def datatype(self, value):
        self._datatype = value

    def is_variable_ref(self) -> bool:
        if isinstance(self.parent(), ClangVariableDecl):
            return True
        return False

    def get_datatype(self) -> object:
        return self.datatype

    def restore_from_xml(self, el: dict, end: dict, pfactory: object) -> None:
        super().restore_from_xml(el, end, pfactory)
        self.datatype = pfactory.get_data_type_manager().find_base_type(self.text, el['id'])

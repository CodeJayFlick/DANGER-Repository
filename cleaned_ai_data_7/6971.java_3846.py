class DecompilerFieldAccess:
    def __init__(self):
        self.variable = None

    def __init__(self, field: 'ClangFieldToken', casts: list) -> None:
        super().__init__()
        self.field = field
        self.casts = casts

    @property
    def variable(self):
        return self._variable

    @variable.setter
    def variable(self, value):
        if isinstance(value, ClangFieldToken):
            self._variable = value
        else:
            raise ValueError("Invalid type for 'variable'")

    def get_parent_data_type(self) -> object:
        field: 'ClangFieldToken' = self.field
        dt = field.get_data_type()
        return dt

    @property
    def data_type(self):
        if not hasattr(self, '_data_type'):
            self._set_data_type()

        return self._data_type

    def _set_data_type(self) -> None:
        field: 'ClangFieldToken' = self.field
        dt = field.get_data_type()
        dt = self._get_base_type(dt)

        if not isinstance(dt, Composite):
            raise ValueError("Invalid data type")

        offset = field.get_offset()
        composite: 'Composite' = dt

        if isinstance(composite, Structure):
            sub_type = composite.get_component_at(offset)
            if sub_type is not None:
                self._data_type = sub_type.get_data_type()

        else:
            component = composite.get_component(offset)

            if component is None:
                return  # Not sure what to do

            dt = component.get_data_type()
            self._data_type = dt

    def _get_base_type(self, data_type: object) -> object:
        if isinstance(data_type, Array):
            return self._get_base_type(data_type.get_data_type())

        elif isinstance(data_type, Pointer):
            base_data_type = data_type.get_data_type()

            if base_data_type is not None:
                return self._get_base_type(base_data_type)

        elif isinstance(data_type, TypeDef):
            return self._get_base_type(data_type.get_base_data_type())

        return data_type

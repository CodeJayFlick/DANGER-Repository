class RegisterTypeInfo:
    def __init__(self, type: 'DataType', pointer_space: 'AddressSpace'):
        self.type = type
        self.settings = type.get_default_settings()
        self.pointer_space = pointer_space

    @property
    def value_class(self) -> type:
        return self.type.value_class(self.settings)

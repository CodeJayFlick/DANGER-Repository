class TypedefDataType:
    def __init__(self, name: str, dt: 'DataType', path=CategoryPath.ROOT):
        self.data_type = dt.clone()
        dt.add_parent(self)
        super().__init__(path, name)

    @property
    def data_type(self) -> 'DataType':
        return self._data_type

    @data_type.setter
    def data_type(self, value: 'DataType'):
        if isinstance(value, BitFieldDataType):
            raise ValueError(f"TypeDef data-type may not be a bitfield: {value.name}")
        elif isinstance(value, FactoryDataType):
            raise ValueError(f"TypeDef data-type may not be a Factory data-tyoe: {value.name}")
        elif isinstance(value, Dynamic):
            raise ValueError(f"TypeDef data-type may not be a Dynamic data-type: {value.name}")

        self._data_type = value

    def get_default_label_prefix(self) -> str:
        return self.name

    def has_language_dependent_length(self) -> bool:
        return self.data_type.has_language_dependent_length()

    def is_equivalent(self, obj: 'DataType') -> bool:
        if not isinstance(obj, TypeDef):
            return False
        if DataTypeUtilities.equals_ignore_conflict(self.name, obj.name):
            return DataTypeUtilities.is_same_or_equivalent_data_type(self.data_type, obj.get_data_type())
        return False

    def get_mnemonic(self, settings: 'Settings') -> str:
        return self.name

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str):
        if not isinstance(value, str):
            raise ValueError("Name must be a string")
        self._name = value

    def get_data_type(self) -> 'DataType':
        return self.data_type

    def get_description(self) -> str:
        return self.data_type.get_description()

    def is_zero_length(self) -> bool:
        return self.data_type.is_zero_length()

    def get_length(self) -> int:
        return self.data_type.get_length()

    def get_representation(self, buf: 'MemBuffer', settings: 'Settings', length: int) -> str:
        return self.data_type.get_representation(buf, settings, length)

    def get_value(self, buf: 'MemBuffer', settings: 'Settings', length: int) -> object:
        return self.data_type.get_value(buf, settings, length)

    def get_value_class(self, settings: 'Settings') -> type:
        return self.data_type.get_value_class(settings)

    def clone(self, dtm: 'DataTypeManager') -> 'TypedefDataType':
        if self.data_type_manager == dtm:
            return self
        return TypedefDataType(self.category_path, self.name, self.data_type, dtm)

    def copy(self, dtm: 'DataTypeManager') -> 'TypedefDataType':
        return TypedefDataType(self.category_path, self.name, self.data_type, dtm)

    def data_type_size_changed(self, dt: 'DataType'):
        if dt == self.data_type:
            notify_size_changed()

    def data_type_alignment_changed(self, dt: 'DataType'):
        if dt == self.data_type:
            notify_alignment_changed()

    def get_base_data_type(self) -> 'DataType':
        if isinstance(self.data_type, TypeDef):
            return (self.data_type).get_base_data_type()
        return self.data_type

    def data_type_deleted(self, dt: 'DataType'):
        if dt == self.data_type:
            notify_deleted()
            self.deleted = True

    @property
    def deleted(self) -> bool:
        return self._deleted

    @deleted.setter
    def deleted(self, value: bool):
        self._deleted = value

    def get_settings_definitions(self) -> list['SettingsDefinition']:
        return self.data_type.get_settings_definitions()

    def data_type_replaced(self, old_dt: 'DataType', new_dt: 'DataType'):
        if isinstance(new_dt, BitFieldDataType):
            raise ValueError(f"TypeDef data-type may not be a bitfield: {new_dt.name}")
        elif isinstance(new_dt, FactoryDataType):
            raise ValueError(f"TypeDef data-type may not be a Factory data-tyoe: {new_dt.name}")
        elif isinstance(new_dt, Dynamic):
            raise ValueError(f"TypeDef data-type may not be a Dynamic data-type: {new_dt.name}")

        self.data_type = new_dt
        old_dt.remove_parent(self)
        new_dt.add_parent(self)

    def depends_on(self, dt: 'DataType') -> bool:
        return (self.data_type == dt) or self.data_type.depends_on(dt)

    def __str__(self):
        return f"typedef {self.name} {self.data_type.name}"

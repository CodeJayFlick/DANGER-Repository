class AbstractDataType:
    def __init__(self, category_path: 'CategoryPath', name: str, data_type_manager: 'DataTypeManager') -> None:
        if not category_path:
            raise ValueError("Category Path is null!")
        if not name or len(name) == 0:
            raise ValueError("Name is null or empty!")

        self.category_path = category_path
        self.name = name
        self.data_type_manager = data_type_manager

    @property
    def category_path(self):
        return self._category_path

    @category_path.setter
    def category_path(self, value: 'CategoryPath') -> None:
        if not value:
            raise ValueError("Category Path is null!")
        self._category_path = value

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str) -> None:
        if not value or len(value) == 0:
            raise ValueError("Name is null or empty!")
        self._name = value

    @property
    def data_type_manager(self):
        return self._data_type_manager

    @data_type_manager.setter
    def data_type_manager(self, value: 'DataTypeManager') -> None:
        if not value:
            raise ValueError("Data Type Manager is null!")
        self._data_type_manager = value

    def get_category_path(self) -> 'CategoryPath':
        return self.category_path

    def get_data_type_manager(self) -> 'DataTypeManager':
        return self.data_type_manager

    def get_data_organization(self) -> 'DataOrganization':
        if not self._data_organization:
            if self.data_type_manager:
                self._data_organization = self.data_type_manager.get_data_organization()
            else:
                self._data_organization = DataOrganizationImpl().get_default_organization()

        return self._data_organization

    def get_data_type_path(self) -> 'DataTypePath':
        return DataTypePath(self.category_path, self.name)

    def get_docs(self) -> URL:
        return None  # do nothing

    def get_name(self) -> str:
        return self.name

    def get_display_name(self) -> str:
        return self.get_name()

    def is_not_yet_defined(self) -> bool:
        return False

    def is_zero_length(self) -> bool:
        return False

    def __str__(self):
        return self.get_display_name()

    def is_deleted(self) -> bool:
        # NOTE: Support for this concept outside of DataTypeDB should not be relied upon
        return False

    def set_name(self, name: str) -> None:
        raise InvalidNameException("Default is immutable")

    def set_name_and_category(self, category_path: 'CategoryPath', name: str) -> None:
        # default is immutable
        pass

    def data_type_size_changed(self, dt: 'DataType') -> None:
        # do nothing
        pass

    def data_type_alignment_changed(self, dt: 'DataType') -> None:
        # do nothing
        pass

    def data_type_deleted(self, dt: 'DataType') -> None:
        # do nothing
        pass

    def add_parent(self, dt: 'DataType') -> None:
        # not-applicable
        pass

    def remove_parent(self, dt: 'DataType') -> None:
        # not-applicable
        pass

    def get_parents(self) -> list['DataType']:
        return []

    def depends_on(self, dt: 'DataType') -> bool:
        return False

    def get_source_archive(self) -> 'SourceArchive':
        return None  # do nothing

    def set_source_archive(self, archive: 'SourceArchive') -> None:
        pass

    def last_change_time(self) -> int:
        return 0  # do nothing

    def last_change_time_in_source_archive(self) -> int:
        return self.last_change_time()

    def get_universal_id(self) -> 'UniversalID':
        return None

    def data_type_name_changed(self, dt: 'DataType', old_name: str) -> None:
        pass

    def replace_with(self, dt: 'DataType') -> None:
        # do nothing
        pass

    def set_last_change_time(self, last_change_time: int) -> None:
        self.last_change_time = last_change_time  # do nothing

    def set_last_change_time_in_source_archive(self, last_change_time_in_source_archive: int) -> None:
        self.set_last_change_time(last_change_time_in_source_archive)

    def set_description(self, description: str) -> None:
        raise UnsupportedOperationException("Immutable")

    def has_language_dependent_length(self) -> bool:
        return False  # not applicable

    def default_label_prefix(self) -> str:
        return ''

    def default_abbreviated_label_prefix(self) -> str:
        return self.default_label_prefix()

    def set_category_path(self, category_path: 'CategoryPath') -> None:
        pass

    def default_label_prefix_for_display(self, buf: MemBuffer, settings: Settings, length: int,
                                           options: DataTypeDisplayOptions) -> str:
        return self.default_label_prefix()

    def default_offcut_label_prefix(self, buf: MemBuffer, settings: Settings, length: int,
                                     options: DataTypeDisplayOptions, offcut_length: int) -> str:
        return self.default_label_prefix_for_display(buf, settings, length, options)

    def is_encodable(self) -> bool:
        return False

    def encode_value(self, value: object, buf: MemBuffer, settings: Settings, length: int) -> bytes:
        raise DataTypeEncodeException("Encoding not supported", value, self)

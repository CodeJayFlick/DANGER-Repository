class BuiltIn(DataTypeImpl):
    STANDARD_SETTINGS_DEFINITIONS = [MutabilitySettingsDefinition.DEF]

    def __init__(self, path: CategoryPath, name: str, data_mgr: DataTypeManager) -> None:
        super().__init__(path if not isinstance(path, type(None)) else CategoryPath.ROOT,
                         name, None, BuiltInSourceArchive.INSTANCE, NO_SOURCE_SYNC_TIME, NO_LAST_CHANGE_TIME, data_mgr)

    def copy(self, dtm: DataTypeManager) -> 'BuiltIn':
        return self.clone(dtm)

    @property
    def setting_defs(self):
        if not hasattr(self, '_setting_defs'):
            self._setting_defs = SettingsDefinition.concat(BuiltIn.STANDARD_SETTINGS_DEFINITIONS,
                                                            self.get_builtin_settings_definitions())
        return self._setting_defs

    def get_builtin_settings_definitions(self) -> list:
        return []

    @property
    def settings_definitions(self):
        return self.setting_defs

    def is_equivalent(self, dt: 'BuiltIn') -> bool:
        if id(dt) == id(self):
            return True
        elif not isinstance(dt, type(None)):
            return False
        else:
            return self.__class__ == dt.__class__

    @property
    def universal_id(self) -> UniversalID:
        return None

    @property
    def last_change_time(self) -> int:
        return 0

    def data_type_size_changed(self, dt: 'BuiltIn') -> None:
        pass

    def set_category_path(self, path: CategoryPath) -> None:
        raise DuplicateNameException()

    def set_name(self, name: str) -> None:
        raise InvalidNameException()

    def add_parent(self, dt: 'BuiltIn') -> None:
        pass

    def remove_parent(self, dt: 'BuiltIn') -> None:
        pass

    @property
    def decompiler_display_name(self):
        return self.name

    def get_c_type_declaration(self, type_name: str) -> str:
        return f"#define {type_name}     {self.get_decomposer_display_name(DecompilerLanguage.C_LANGUAGE)}"

    def get_c_type_declaration(self, dt: 'BuiltIn', signed: bool = False) -> str:
        if isinstance(dt, Dynamic):
            return None
        elif isinstance(dt, FactoryDataType):
            return f"typedef int[{dt.length}]{type_name};"
        else:
            return self.get_c_type_declaration(type_name=type_name)

    def get_c_type_declaration(self, data_organization: DataOrganization) -> str:
        if isinstance(data_organization, Dynamic):
            return None
        elif isinstance(data_organization, FactoryDataType):
            return f"typedef int[{data_organization.length}]{self.name};"
        else:
            return self.get_c_type_declaration(type_name=self.name)

    def depends_on(self, dt: 'BuiltIn') -> bool:
        return False

class DataTypeImpl:
    pass

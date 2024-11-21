class DBTraceData:
    TABLE_NAME = "Data"
    LANGUAGE_COLUMN_NAME = "Language"
    DATATYPE_COLUMN_NAME = "DataType"

    def __init__(self, space: 'DBTraceCodeSpace', tree: 'DBTraceAddressSnapRangePropertyMapTree[?, ?]', store: '?', record: 'DBRecord'):
        super().__init__(space, tree, store, record)

    @property
    def language(self):
        return self._language

    @language.setter
    def language(self, value):
        if not isinstance(value, Language):
            raise ValueError("Language must be an instance of Language")
        self._language = value
        self.langKey = space.manager.languageManager.get_key_for_language(value)
        self.dataTypeID = space.dataTypeManager.get_resolved_id(value.default_data_type())
        self.baseDataType = get_base_data_type(self.dataType)
        self.defaultSettings = self.dataType.default_settings

    @property
    def dataTypeID(self):
        return self._dataTypeID

    @dataTypeID.setter
    def dataTypeID(self, value):
        if not isinstance(value, int) or value < 0:
            raise ValueError("Data type ID must be a non-negative integer")
        self._dataTypeID = value
        self.dataType = space.dataTypeManager.get_data_type_by_id(value)
        self.baseDataType = get_base_data_type(self.dataType)

    @property
    def baseDataType(self):
        return self._baseDataType

    @baseDataType.setter
    def baseDataType(self, value):
        if not isinstance(value, DataType) or value is None:
            raise ValueError("Base data type must be an instance of Data Type")
        self._baseDataType = value

    @property
    def defaultSettings(self):
        return self._defaultSettings

    @defaultSettings.setter
    def defaultSettings(self, value):
        if not isinstance(value, Settings) or value is None:
            raise ValueError("Default settings must be an instance of Settings")
        self._defaultSettings = value

    def fresh(self, created: bool):
        super().fresh(created)
        if created:
            return
        try:
            language = space.manager.language_manager.get_language_by_key(self.langKey)
            if language is None:
                raise IOException("Data table is corrupt. Missing langauge: " + str(self.langKey))
            self.dataType = space.data_type_manager.get_data_type(self.dataTypeID)
            if self.dataType is None:
                raise IOException("Data table is corrupt. Missing datatype: " + str(self.dataTypeID))
        except Exception as e:
            print(str(e))

    def set_record_value(self, value):
        pass

    def get_record_value(self):
        return self

    @property
    def dataType(self):
        return self._dataType

    @dataType.setter
    def dataType(self, value):
        if not isinstance(value, DataType) or value is None:
            raise ValueError("Data type must be an instance of Data Type")
        self._dataType = value

    def get_data_type_length(self):
        if isinstance(self.baseDataType, Pointer):
            return language.default_data_space.get_pointer_size()
        else:
            return self.dataType.length()

    @staticmethod
    def get_base_data_type(dt: 'DataType'):
        if isinstance(dt, TypeDef):
            return dt.get_base_data_type()
        else:
            return dt

    def delete(self):
        try:
            space.data_map_space.delete_data(self)
        except Exception as e:
            print(str(e))
        finally:
            space.defined_data.unit_removed(self)

    @property
    def end_snap(self):
        pass  # TODO: Implement this method

    def set_end_snap(self, value):
        old_span = self.get_lifespan()
        super().set_end_snap(value)
        try:
            space.defined_data.unit_span_changed(old_span, self)
        except Exception as e:
            print(str(e))

    @property
    def language_key(self):
        return self.langKey

    @property
    def data_type_length(self):
        pass  # TODO: Implement this method

    def __str__(self):
        return do_to_string()

    def get_root(self):
        return self

    def get_parent_offset(self):
        return 0

    def get_component_cache(self):
        if not hasattr(self, 'componentCache'):
            componentCache = [AbstractDBTraceDataComponent() for _ in range(get_num_components())]
            setattr(self, 'componentCache', componentCache)
        return getattr(self, 'componentCache')

    @property
    def parent_offset(self):
        return 0

    # ... other methods ...

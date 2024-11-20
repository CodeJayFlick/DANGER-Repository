class TestDoubleDataTypeManagerService:
    def get_data_type_managers(self):
        raise NotImplementedError()

    def get_sorted_data_type_list(self):
        raise NotImplementedError()

    def get_data_type(self, filter_text: str) -> 'DataType':
        raise NotImplementedError()

    def get_built_in_data_types_manager(self) -> 'DataTypeManager':
        raise NotImplementedError()

    def get_favorites(self) -> List['DataType']:
        raise NotImplementedError()

    def add_data_type_manager_change_listener(self, listener):
        raise NotImplementedError()

    def remove_data_type_manager_change_listener(self, listener):
        raise NotImplementedError()

    def set_recently_used(self, dt: 'DataType'):
        raise NotImplementedError()

    def get_recently_used(self) -> 'DataType':
        raise NotImplementedError()

    def get_editor_help_location(self, data_type: 'DataType') -> HelpLocation:
        raise NotImplementedError()

    def is_editable(self, dt: 'DataType') -> bool:
        raise NotImplementedError()

    def edit(self, dt: 'DataType'):
        raise NotImplementedError()

    def close_archive(self, dtm: 'DataTypeManager'):
        raise NotImplementedError()

    def open_data_type_archive(self, archive_name: str) -> Archive:
        try:
            return super().open_data_type_archive(archive_name)
        except (IOException, DuplicateIdException):
            raise

    def open_archive(self, data_type_archive: 'DataTypeArchive') -> Archive:
        raise NotImplementedError()

    def open_archive(self, file: File, acquire_write_lock: bool) -> Archive:
        try:
            return super().open_archive(file, acquire_write_lock)
        except (IOException, DuplicateIdException):
            raise

    def set_data_type_selected(self, data_type: 'DataType'):
        raise NotImplementedError()

    def get_data_type(self, selected_path: TreePath) -> 'DataType':
        raise NotImplementedError()

    def get_possible_equate_names(self, value: int) -> Set[str]:
        raise NotImplementedError()

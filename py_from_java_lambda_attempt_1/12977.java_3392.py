Here is the translation of the given Java code into equivalent Python:

```Python
class TestDummyDataTypeManager:
    def get_universal_id(self):
        # stub
        return None

    def contains_category(self, path: 'CategoryPath'):
        # stub
        return False

    def get_unique_name(self, path: 'CategoryPath', base_name: str) -> str:
        # stub
        return None

    def resolve(self, data_type: 'DataType', handler: 'DataTypeConflictHandler') -> 'DataType':
        # stub
        return None

    def add_data_type(self, data_type: 'DataType', handler: 'DataTypeConflictHandler') -> 'DataType':
        # stub
        return None

    def add_data_types(self, data_types: list['DataType'], handler: 'DataTypeConflictHandler', monitor):
        # stub

    def get_all_data_types(self) -> iter['DataType']:
        # stub
        return None

    def get_all_structures(self) -> iter['Structure']:
        # stub
        return None

    def find_data_types(self, name: str, list_to_fill: list['DataType']):
        # stub

    def replace_data_type(self, existing_dt: 'DataType', replacement_dt: 'DataType', update_category_path: bool):
        # stub
        return None

    def get_data_type(self, data_type_path: str) -> 'DataType':
        # stub
        return None

    def find_data_type(self, data_type_path: str) -> 'DataType':
        # stub
        return None

    def get_resolved_id(self, dt: 'DataType') -> int:
        # stub
        return 0

    def is_updatable(self):
        # stub
        return False

    def close(self):
        # stub

    def get_pointer(self, datatype: 'DataType', size: int) -> 'Pointer':
        # stub
        return None

    def get_root_category(self) -> 'Category':
        # stub
        return None

    def is_favorite(self, datatype: 'DataType') -> bool:
        # stub
        return False

    def set_favorite(self, datatype: 'DataType', is_favorite: bool):
        # stub

    def flush_events(self):
        # stub

    def start_transaction(self, description: str) -> int:
        # stub
        return 0

    def end_transaction(self, transaction_id: int, commit: bool):
        # stub

    def get_data_types_for_path(self, path: 'CategoryPath') -> list['DataType']:
        # stub
        return None

    def find_enum_value_names(self, value: int, enum_value_names: set[str]):
        # stub

    def get_last_change_time_for_my_manager(self) -> int:
        # stub
        return 0

    def associate_data_type_with_archive(self, datatype: 'DataType', archive):
        # stub

    def disassociate(self, datatype: 'DataType'):
        # stub

    def update_source_archive_name(self, source_id: str, name: str) -> bool:
        # stub
        return False

    def get_local_source_archive(self) -> 'SourceArchive':
        # stub
        return None

    def remove_source_archive(self, archive):
        # stub

    def resolve_source_archive(self, source_archive: 'SourceArchive') -> 'SourceArchive':
        # stub
        return None

    def set_name(self, name: str):
        # stub

    def get_name(self) -> str:
        # stub
        return None

```

Note that Python does not support the exact equivalent of Java's `@Override` annotation. However, you can use a docstring to indicate which method is being overridden in your subclass.

Also note that some methods are identical or very similar across both languages (e.g., `getUniversalID`, `containsCategory`, etc.), so it may be beneficial to create an abstract base class with these common methods and then have the specific implementation classes inherit from this.
Here is the translation of the given Java code into Python:

```Python
class TypedefDBAdapterV0:
    VERSION = 0
    V0_TYPEDEF_DT_ID_COL = 0
    V0_TYPEDEF_NAME_COL = 1
    V0_TYPEDEF_CAT_COL = 2
    
    def __init__(self, handle):
        self.table = handle.get_table("Typedef")
        
        if not self.table:
            raise VersionException(f"Missing Table: {TYPEDEF_TABLE_NAME}")
            
        version = self.table.schema.version
        
        if version != self.VERSION:
            msg = f"Expected version {self.VERSION} for table {TYPEDEF_TABLE_NAME}, but got {version}"
            
            if version < self.VERSION:
                raise VersionException(msg, "OLDER_VERSION", True)
                
            raise VersionException(msg, "NEWER_VERSION", False)

    def delete_table(self, handle):
        handle.delete_table("Typedef")

    def create_record(self, data_type_id: int, name: str, category_id: int, source_archive_id: int, 
                      source_data_type_id: int, last_change_time: int) -> None:
        raise Exception(f"Not allowed to update prior version {self.VERSION} of {TYPEDEF_TABLE_NAME} table.")

    def get_record(self, typedef_id: int):
        return self.translate_record(self.table.get_record(typedef_id))

    def get_records(self):
        return TranslatedRecordIterator(self.table.iterator(), self)

    def update_record(self, record: DBRecord, set_last_change_time: bool) -> None:
        raise Exception("Not allowed to update prior version {self.VERSION} of {TYPEDEF_TABLE_NAME} table.")

    def remove_record(self, data_id: int):
        return self.table.delete_record(data_id)

    def get_record_ids_in_category(self, category_id: int):
        return self.table.find_records(LongField(category_id), V0_TYPEDEF_CAT_COL)

    def get_record_ids_for_source_archive(self, archive_id: int) -> None:
        return []

    def translate_record(self, old_rec: DBRecord):
        if not old_rec:
            return None
        
        rec = TypedefDBAdapter.SCHEMAS.create_record(old_rec.key)
        
        rec.set_long_value(V0_TYPEDEF_DT_ID_COL, old_rec.get_long_value(V0_TYPEDEF_DT_ID_COL))
        rec.set_string(V0_TYPEDEF_NAME_COL, old_rec.get_string(V0_TYPEDEF_NAME_COL))
        rec.set_long_value(V0_TYPEDEF_CAT_COL, old_rec.get_long_value(V0_TYPEDEF_CAT_COL))
        
        return rec

    def get_record_with_ids(self, source_id: UniversalID, datatype_id: UniversalID) -> None:
        return None
```

Note that Python does not have direct equivalent of Java's `throws` keyword. Instead, you can use the built-in exception handling mechanism to handle exceptions in your code.
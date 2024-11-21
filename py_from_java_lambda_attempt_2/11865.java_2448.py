Here is the translation of the given Java code into Python:

```Python
class CompositeDBAdapterV2V4:
    VERSION = 4
    MIN_READ_ONLY_VERSION = 2
    
    V2V4_COMPOSITE_NAME_COL = 0
    V2V4_COMPOSITE_COMMENT_COL = 1
    V2V4_COMPOSITE_IS_UNION_COL = 2
    V2V4_COMPOSITE_CAT_COL = 3
    V2V4_COMPOSITE_LENGTH_COL = 4
    V2V4_COMPOSITE_NUM_COMPONENTS_COL = 5
    V2V4_COMPOSITE_SOURCE_ARCHIVE_ID_COL = 6
    V2V4_COMPOSITE_UNIVERSAL_DT_ID_COL = 7
    V2V4_COMPOSITE_SOURCE_SYNC_TIME_COL = 8
    V2V4_COMPOSITE_LAST_CHANGE_TIME_COL = 9
    V2V4_COMPOSITE_PACK_COL = 10
    
    def __init__(self, handle):
        self.composite_table = handle.get_table("Composite")
        
        if not self.composite_table:
            raise VersionException(f"Missing Table: {COMPOSITE_TABLE_NAME}")
            
        version = self.composite_table.schema.version
        if version < MIN_READ_ONLY_VERSION:
            raise VersionException(VersionException.OLDER_VERSION, True)
        elif version > VERSION:
            msg = f"Expected version {VERSION} for table {COMPOSITE_TABLE_NAME}, but got {version}"
            raise VersionException(msg, VersionException.NEWER_VERSION, False)

    def get_version(self):
        return self.composite_table.schema.version

    def get_record_count(self):
        return self.composite_table.record_count

    def create_record(self, name: str, comments: str, is_union: bool, category_id: int, length: int,
                      computed_alignment: int, source_archive_id: long, source_data_type_id: long,
                      last_change_time: long, pack_value: int, min_alignment: int) -> DBRecord:
        raise UnsupportedOperationException(f"Not allowed to update prior version #{self.VERSION} of {COMPOSITE_TABLE_NAME} table.")

    def get_record(self, data_type_id: long) -> DBRecord:
        return self.translate_record(self.composite_table.get_record(data_type_id))

    def get_records(self) -> RecordIterator:
        return TranslatedRecordIterator(self.composite_table.iterator(), self)

    def update_record(self, record: DBRecord, set_last_change_time: bool) -> None:
        raise UnsupportedOperationException()

    def remove_record(self, composite_id: long) -> None:
        raise UnsupportedOperationException(f"Not allowed to update prior version #{self.VERSION} of {COMPOSITE_TABLE_NAME} table.")

    @staticmethod
    def delete_table(handle):
        handle.delete_table("Composite")

    def get_record_ids_in_category(self, category_id: int) -> Field[]:
        return self.composite_table.find_records(LongField(category_id), V2V4_COMPOSITE_CAT_COL)

    def get_record_ids_for_source_archive(self, archive_id: long) -> Field[]:
        return self.composite_table.find_records(LongField(archive_id), V2V4_COMPOSITE_SOURCE_ARCHIVE_ID_COL)

    @staticmethod
    def translate_record(old_rec):
        if old_rec is None:
            return None
        
        rec = CompositeDBAdapter.CompositeSchema.create_record(old_rec.key)
        
        rec.set_string(V2V4_COMPOSITE_NAME_COL, old_rec.get_string(V2V4_COMPOSITE_NAME_COL))
        rec.set_string(V2V4_COMPOSITE_COMMENT_COL, old_rec.get_string(V2V4_COMPOSITE_COMMENT_COL))
        rec.set_boolean_value(V2V4_COMPOSITE_IS_UNION_COL, old_rec.get_boolean_value(V2V4_COMPOSITE_IS_UNION_COL))
        rec.set_long_value(V2V4_COMPOSITE_CAT_COL, old_rec.get_long_value(V2V4_COMPOSITE_CAT_COL))
        rec.set_int_value(V2V4_COMPOSITE_LENGTH_COL, old_rec.get_int_value(V2V4_COMPOSITE_LENGTH_COL))
        rec.set_int_value(V2V4_COMPOSITE_ALIGN_MENT_COL, -1)
        rec.set_int_value(V2V4_COMPOSITE_NUM_COMPONENTS_COL, old_rec.get_int_value(V2V4_COMPOSITE_NUM_COMPONENTS_COL))
        rec.set_long_value(V2V4_COMPOSITE_SOURCE_ARCHIVE_ID_COL, old_rec.get_long_value(V2V4_COMPOSITE_SOURCE_ARCHIVE_ID_COL))
        rec.set_long_value(V2V4_COMPOSITE_UNIVERSAL_DT_ID_COL, old_rec.get_long_value(V2V4_COMPOSITE_UNIVERSAL_DT_ID_COL))
        rec.set_long_value(V2V4_COMPOSITE_SOURCE_SYNC_TIME_COL, old_rec.get_long_value(V2V4_COMPOSITE_SOURCE_SYNC_TIME_COL))
        rec.set_long_value(V2V4_COMPOSITE_LAST_CHANGE_TIME_COL, old_rec.get_long_value(V2V4_COMPOSITE_LAST_CHANGE_TIME_COL))
        rec.set_int_value(V2V4_COMPOSITE_PACKING_COL, old_rec.get_int_value(V2V4_COMPOSITE_PACK_COL))
        rec.set_int_value(V2V4_COMPOSITE_MIN_ALIGN_MENT_COL, old_rec.get_int_value(V2V4_COMPOSITE_MIN_ALIGN_MENT_COL))
        
        return rec

    def get_record_with_ids(self, source_id: UniversalID, data_type_id: UniversalID) -> DBRecord:
        keys = self.composite_table.find_records(LongField(data_type_id.value), V2V4_COMPOSITE_UNIVERSAL_DT_ID_COL)

        for key in keys:
            record = self.composite_table.get_record(key)
            
            if record.get_long_value(V2V4_COMPOSITE_SOURCE_ARCHIVE_ID_COL) == source_id.value:
                return self.translate_record(record)
        
        return None
```

Note that this is a direct translation of the Java code into Python, and may not be perfect. For example, some Java-specific features like `@Override` are not present in Python. Additionally, error handling and exception types may need to be adjusted for compatibility with Python's try-except blocks.
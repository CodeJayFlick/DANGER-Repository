class CompositeDBAdapterV1:
    VERSION = 1
    V1_COMPOSITE_NAME_COL = 0
    V1_COMPOSITE_COMMENT_COL = 1
    V1_COMPOSITE_IS_UNION_COL = 2
    V1_COMPOSITE_CAT_COL = 3
    V1_COMPOSITE_LENGTH_COL = 4
    V1_COMPOSITE_NUM_COMPONENTS_COL = 5
    V1_COMPOSITE_SOURCE_ARCHIVE_ID_COL = 6
    V1_COMPOSITE UNIVERSAL_DT_ID_COL = 7
    V1_COMPOSITE_SOURCE_SYNC_TIME_COL = 8
    V1_COMPOSITE_LAST_CHANGE_TIME_COL = 9

    def __init__(self, handle):
        self.composite_table = handle.get_table("Composite")
        if not self.composite_table:
            raise VersionException(f"Missing Table: {COMPOSITE_TABLE_NAME}")
        version = self.composite_table.schema.version
        if version != self.VERSION:
            msg = f"Expected version {self.VERSION} for table {COMPOSITE_TABLE_NAME}, but got {version}"
            if version < self.VERSION:
                raise VersionException(msg, True)
            else:
                raise VersionException(msg, False)

    def get_version(self):
        return self.composite_table.schema.version

    def get_record_count(self):
        return self.composite_table.record_count

    def create_record(self, name: str, comments: str, is_union: bool, category_id: int,
                      length: int, computed_alignment: int, source_archive_id: int,
                      source_data_type_id: int, last_change_time: int, pack_value: int,
                      min_alignment: int) -> None:
        raise UnsupportedOperationException(f"Not allowed to update prior version #{self.VERSION} of {COMPOSITE_TABLE_NAME} table.")

    def get_record(self, data_type_id: int) -> DBRecord:
        return self.translate_record(self.composite_table.get_record(data_type_id))

    def translate_record(self, old_rec):
        if not old_rec:
            return None
        rec = CompositeDBAdapter.COMPOSITE_SCHEMA.create_record(old_rec.key)
        rec[V1_COMPOSITE_NAME_COL] = old_rec[V1_COMPOSITE_NAME_COL]
        rec[V1_COMPOSITE_COMMENT_COL] = old_rec[V1_COMPOSITE_COMMENT_COL]
        rec[V1_COMPOSITE_IS_UNION_COL] = old_rec[V1_COMPOSITE_IS_UNION_COL]
        rec[V1_COMPOSITE_CAT_COL] = old_rec[V1_COMPOSITE_CAT_COL]
        rec[V1_COMPOSITE_LENGTH_COL] = old_rec[V1_COMPOSITE_LENGTH_COL]
        rec[V1_COMPOSITE_NUM_COMPONENTS_COL] = old_rec[V1_COMPOSITE_NUM_COMPONENTS_COL]
        rec[V1_COMPOSITE_SOURCE_ARCHIVE_ID_COL] = old_rec[V1_COMPOSITE_SOURCE_ARCHIVE_ID_COL]
        rec[V1_COMPOSITE_UNIVERSAL_DT_ID_COL] = old_rec[V1_COMPOSITE_UNIVERSAL_DT_ID_COL]
        rec[V1_COMPOSITE_SOURCE_SYNC_TIME_COL] = old_rec[V1_COMPOSITE_SOURCE_SYNC_TIME_COL]
        rec[V1_COMPOSITE_LAST_CHANGE_TIME_COL] = old_rec[V1_COMPOSITE_LAST_CHANGE_TIME_COL]
        return rec

    def get_records(self) -> RecordIterator:
        return TranslatedRecordIterator(self.composite_table.iterator(), self)

    def update_record(self, record: DBRecord, set_last_change_time: bool) -> None:
        raise UnsupportedOperationException()

    def remove_record(self, composite_id: int) -> None:
        raise UnsupportedOperationException(f"Not allowed to update prior version #{self.VERSION} of {COMPOSITE_TABLE_NAME} table.")

    def delete_table(self, handle):
        handle.delete_table("Composite")

    def get_record_ids_in_category(self, category_id: int) -> Field:
        return self.composite_table.find_records(LongField(category_id), V1_COMPOSITE_CAT_COL)

    def get_record_ids_for_source_archive(self, archive_id: int) -> Field:
        return self.composite_table.find_records(LongField(archive_id), V1_COMPOSITE_SOURCE_ARCHIVE_ID_COL)

class PointerDBAdapterV1:
    VERSION = 1
    V1_PTR_DT_ID_COL = 0
    V1_PTR_CATEGORY_COL = 1

    def __init__(self, handle):
        self.table = handle.get_table("Pointer ID")
        if not self.table:
            raise VersionException(f"Missing Table: {POINTER_ TABLE_NAME}")
        version_number = self.table.schema.version
        if version_number != self.VERSION:
            raise VersionException(
                f"Expected version {self.VERSION} for table {POINTER_TABLE_NAME}, but got {version_number}")

    def translate_record(self, old_rec):
        if not old_rec:
            return None
        rec = PointerDBAdapterV1.SCHEMA.create_record(old_rec.key)
        rec[V1_PTR_DT_ID_COL] = old_rec.get_long_value(V1_PTR_DT_ID_COL)
        rec[V1_PTR_CATEGORY_COL] = old_rec.get_long_value(V1_PTR_CATEGORY_COL)
        rec[PTR_LENGTH_COL] = -1
        return rec

    def create_record(self, data_type_id: int, category_id: int, length: int):
        raise NotImplementedError()

    def get_record(self, pointer_id: int) -> dict:
        record = self.table.get_record(pointer_id)
        if not record:
            return None
        return self.translate_record(record)

    def get_records(self) -> list[dict]:
        iterator = self.table.iterator()
        translated_iterator = TranslatedRecordIterator(iterator, self)
        records = []
        for rec in translated_iterator:
            records.append(rec)
        return records

    def remove_record(self, pointer_id: int):
        raise NotImplementedError()

    def update_record(self, record: dict):
        raise NotImplementedError()

    def get_record_ids_in_category(self, category_id: int) -> list[dict]:
        return self.table.find_records(LongField(category_id), V1_PTR_CATEGORY_COL)

    def delete_table(self, handle):
        handle.delete_table("Pointer ID")

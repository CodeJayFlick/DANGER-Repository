class PointerDBAdapterV2:
    VERSION = 2

    def __init__(self, handle, create=False):
        if create:
            self.table = handle.create_table('POINTER_TABLE_NAME', 'SCHEMA', ['PTR_CATEGORY_COL'])
        else:
            try:
                self.table = handle.get_table('POINTER_TABLE_NAME')
            except KeyError as e:
                raise VersionException(f"Missing Table: {e}")
            if not self.table or self.table.schema.version != VERSION:
                version = self.table.schema.version
                if version < VERSION:
                    raise VersionException(True)
                else:
                    raise VersionException(VersionException.NEWER_VERSION, False)

    def create_record(self, data_type_id, category_id, length):
        try:
            table_key = self.table.key
            key = DataTypeManagerDB.create_key(DataTypeManagerDB.POINTER, table_key)
            record = SCHEMA.create_record(key)
            record.set_long_value('PTR_DT_ID_COL', data_type_id)
            record.set_long_value('PTR_CATEGORY_COL', category_id)
            record.set_byte_value('PTR_LENGTH_COL', length)
            self.table.put_record(record)
        except Exception as e:
            raise IOException(f"Error creating record: {e}")
        return record

    def get_record(self, pointer_id):
        try:
            return self.table.get_record(pointer_id)
        except KeyError as e:
            raise IOException(f"Record not found: {e}")

    def get_records(self):
        try:
            return self.table.iterator()
        except Exception as e:
            raise IOException(f"Error getting records: {e}")

    def remove_record(self, pointer_id):
        try:
            return self.table.delete_record(pointer_id)
        except KeyError as e:
            raise IOException(f"Record not found: {e}")

    def update_record(self, record):
        try:
            self.table.put_record(record)
        except Exception as e:
            raise IOException(f"Error updating record: {e}")

    def get_record_ids_in_category(self, category_id):
        try:
            return self.table.find_records(LongField(category_id), 'PTR_CATEGORY_COL')
        except Exception as e:
            raise IOException(f"Error getting records in category: {e}")

    def delete_table(self, handle):
        try:
            handle.delete_table('POINTER_TABLE_NAME')
        except KeyError as e:
            raise IOException(f"Table not found: {e}")

    def translate_record(self, rec):
        return rec

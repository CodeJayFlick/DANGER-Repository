class BookmarkTypeDBAdapterV0:
    def __init__(self, db_handle, create):
        if create:
            self.table = db_handle.create_table(TABLE_NAME, SCHEMA)
        else:
            try:
                self.table = db_handle.get_table(TABLE_NAME)
                if not self.table:
                    raise VersionException(True)
                elif self.table.schema_version != 0:
                    raise VersionException(False)
            except Exception as e:
                print(f"An error occurred: {e}")

    def get_records(self):
        try:
            recs = []
            for record in self.table.records():
                recs.append(record)
            return recs
        except Exception as e:
            print(f"An error occurred: {e}")
            return []

    def add_type(self, type_id, type_name):
        try:
            rec = SCHEMA.create_record(type_id)
            rec.set_string(TYPE_NAME_COL, type_name)
            self.table.put_record(rec)
        except Exception as e:
            print(f"An error occurred: {e}")

    def delete_record(self, record_id):
        try:
            self.table.delete_record(record_id)
        except Exception as e:
            print(f"An error occurred: {e}")

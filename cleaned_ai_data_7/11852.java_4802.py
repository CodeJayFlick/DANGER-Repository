class ArrayDBAdapterV1:
    VERSION = 1
    ARRAY_TABLE_NAME = "Arrays"
    V1_ARRAY_DT_ID_COL = 0
    V1_ARRAY_DIM_COL = 1
    V1_ARRAY_ELEMENT_LENGTH_COL = 2
    V1_ARRAY_CAT_COL = 3

    def __init__(self, handle, create=False):
        if create:
            self.table = handle.create_table(ARRAY_TABLE_NAME)
        else:
            try:
                self.table = handle.get_table(ARRAY_TABLE_NAME)
            except KeyError as e:
                raise VersionException("Missing Table: " + ARRAY_TABLE_NAME) from e
            if not self.table or self.table.schema.version != VERSION:
                raise VersionException(VersionException.NEWER_VERSION, False)

    def create_record(self, data_type_id, number_of_elements, length, cat_id):
        try:
            table_key = self.table.key
            #if table_key <= DataManager.VOID_DATATYPE_ID:
            	#table_key += 1
            key = DataTypeManagerDB.create_key(DataTypeManagerDB.ARRAY, table_key)
            record = self.table.schema.create_record(key)
            record[V1_ARRAY_DT_ID_COL] = data_type_id
            record[V1_ARRAY_DIM_COL] = number_of_elements
            record[V1_ARRAY_ELEMENT_LENGTH_COL] = length
            record[V1_ARRAY_CAT_COL] = cat_id
            self.table.put_record(record)
            return record
        except Exception as e:
            raise IOException("Error creating record") from e

    def get_record(self, array_id):
        try:
            return self.table.get_record(array_id)
        except Exception as e:
            raise IOException("Error getting record") from e

    def get_records(self):
        try:
            return self.table.iterator()
        except Exception as e:
            raise IOException("Error getting records") from e

    def remove_record(self, data_id):
        try:
            return self.table.delete_record(data_id)
        except Exception as e:
            raise IOException("Error removing record") from e

    def update_record(self, record):
        try:
            self.table.put_record(record)
        except Exception as e:
            raise IOException("Error updating record") from e

    def delete_table(self, handle):
        try:
            handle.delete_table(ARRAY_TABLE_NAME)
        except Exception as e:
            raise IOException("Error deleting table") from e

    def get_record_ids_in_category(self, category_id):
        try:
            return self.table.find_records(LongField(category_id), V1_ARRAY_CAT_COL)
        except Exception as e:
            raise IOException("Error getting record IDs in category") from e

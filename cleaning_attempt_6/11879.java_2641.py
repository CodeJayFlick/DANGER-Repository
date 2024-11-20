class EnumDBAdapterV1:
    VERSION = 1
    
    # Enum Columns
    V1_ENUM_NAME_COL = 0
    V1_ENUM_COMMENT_COL = 1
    V1_ENUM_CAT_COL = 2
    V1_ENUM_SIZE_COL = 3
    V1_ENUM_SOURCE_ARCHIVE_ID_COL = 4
    V1_ENUM_UNIVERSAL_DT_ID_COL = 5
    V1_ENUM_SOURCE_SYNC_TIME_COL = 6
    V1_ENUM_LAST_CHANGE_TIME_COL = 7

    V1_ENUM_SCHEMA = {
        "Name": {"type": str},
        "Comment": {"type": str},
        "Category ID": {"type": int, "length": 8},
        "Size": {"type": int, "length": 1},
        "Source Archive ID": {"type": int, "length": 8},
        "Source Data Type ID": {"type": int, "length": 8},
        "Source Sync Time": {"type": int, "length": 8},
        "Last Change Time": {"type": int, "length": 8}
    }

    def __init__(self, handle, create):
        if create:
            self.enum_table = handle.create_table("Enum ID", V1_ENUM_SCHEMA)
        else:
            try:
                self.enum_table = handle.get_table("Enum ID")
            except KeyError as e:
                raise VersionException(f"Missing Table: {e}")
            version = self.enum_table.schema["version"]
            if version != self.VERSION:
                msg = f"Expected version {self.VERSION} for table 'Enum ID' but got {version}"
                if version < self.VERSION:
                    raise VersionException(msg, "OLDER_VERSION", True)
                else:
                    raise VersionException(msg, "NEWER_VERSION", False)

    def create_record(self, name, comments, category_id, size, source_archive_id, 
                      source_data_type_id, last_change_time):
        record = {"Name": name, "Comment": comments}
        for col in self.V1_ENUM_SCHEMA:
            if col == "Category ID":
                record[col] = category_id
            elif col == "Size":
                record[col] = size
            elif col == "Source Archive ID":
                record[col] = source_archive_id
            elif col == "Source Data Type ID":
                record[col] = source_data_type_id
            elif col == "Last Change Time":
                record[col] = last_change_time
        self.enum_table.put_record(record)
        return record

    def get_record(self, enum_id):
        try:
            return self.enum_table.get_record(enum_id)
        except KeyError as e:
            raise IOException(f"Record {enum_id} not found")

    def get_records(self):
        return iter(self.enum_table)

    def update_record(self, record, set_last_change_time=False):
        if set_last_change_time:
            record["Last Change Time"] = int((datetime.datetime.now()).timestamp())
        self.enum_table.put_record(record)

    def remove_record(self, enum_id):
        try:
            return self.enum_table.delete_record(enum_id)
        except KeyError as e:
            raise IOException(f"Record {enum_id} not found")

    def delete_table(self, handle):
        handle.delete_table("Enum ID")

    def get_record_ids_in_category(self, category_id):
        return [record["Key"] for record in self.enum_table.find_records({"Category ID": category_id})]

    def get_record_ids_for_source_archive(self, archive_id):
        return [record["Key"] for record in self.enum_table.find_records({"Source Archive ID": archive_id})]

    def get_record_with_ids(self, source_id, data_type_id):
        records = list(self.enum_table.find_records({"Source Data Type ID": data_type_id}))
        for record in records:
            if record["Source Archive ID"] == source_id:
                return record
        return None

class VersionException(Exception):
    def __init__(self, message, version=None, is_older=False):
        super().__init__(message)
        self.version = version
        self.is_older = is_older

class IOException(Exception):
    pass

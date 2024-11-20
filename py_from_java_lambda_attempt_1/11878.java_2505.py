Here is the translation of the given Java code into Python:

```Python
class EnumDBAdapterV0:
    VERSION = 0
    
    ENUM_NAME_COL = 0
    ENUM_COMMENT_COL = 1
    ENUM_CAT_COL = 2
    ENUM_SIZE_COL = 3

    V0_ENUM_SCHEMA = Schema(VERSION, "Enum ID", [
        StringField("Name"),
        StringField("Comment"),
        LongField("Category ID"),
        ByteField("Size")
    ])

    def __init__(self, handle):
        self.enum_table = handle.get_table("Enumeration Table")
        
        if not self.enum_table:
            raise VersionException(f"Missing table: {ENUM_TABLE_NAME}")
            
        version = self.enum_table.schema.version
        if version != VERSION:
            msg = f"Expected version {VERSION} for table {ENUM_TABLE_NAME}, but got {version}"
            if version < VERSION:
                raise VersionException(msg, "older_version", True)
            else:
                raise VersionException(msg, "newer_version", False)

    def create_record(self, name: str, comments: str, category_id: int, size: int):
        return Exception("Not allowed to update prior version #{} of {} table.".format(VERSION, ENUM_TABLE_NAME))

    def get_record(self, enum_id: int) -> dict:
        record = self.enum_table.get_record(enum_id)
        if not record:
            raise Exception(f"Record with ID {enum_id} does not exist")
        
        return {
            "Name": record[ENUM_NAME_COL],
            "Comment": record[ENUM_COMMENT_COL],
            "Category ID": record[ENUM_CAT_COL],
            "Size": record[ENUM_SIZE_COL]
        }

    def get_records(self) -> list:
        records = []
        for rec in self.enum_table.iterator():
            if not rec:
                continue
            records.append({
                "Name": rec[ENUM_NAME_COL],
                "Comment": rec[ENUM_COMMENT_COL],
                "Category ID": rec[ENUM_CAT_COL],
                "Size": rec[ENUM_SIZE_COL]
            })
        
        return records

    def update_record(self, record: dict):
        raise Exception("Not allowed to update prior version #{} of {} table.".format(VERSION, ENUM_TABLE_NAME))

    def remove_record(self, enum_id: int) -> bool:
        if self.enum_table.delete_record(enum_id):
            return True
        else:
            return False

    def delete_table(self, handle):
        try:
            handle.delete_table("Enumeration Table")
        except Exception as e:
            print(f"Error deleting table: {e}")

    def get_records_in_category(self, category_id: int) -> list:
        records = self.enum_table.find_records(LongField(category_id), ENUM_CAT_COL)
        
        return [record for record in records]

    def get_record_ids_for_source_archive(self, archive_id: int):
        return []

    def translate_record(self, old_rec: dict) -> dict:
        if not old_rec:
            return None
        
        rec = {
            "Name": old_rec["Name"],
            "Comment": old_rec["Comment"],
            "Category ID": old_rec[ENUM_CAT_COL],
            "Size": old_rec[ENUM_SIZE_COL]
        }
        
        return rec

    def get_record_with_ids(self, source_id: int, datatype_id: int):
        return None
```

Please note that Python does not have direct equivalent of Java's `enum` and some other features.
Here is the translation of the given Java code into Python:

```Python
class VTMatchTableDBAdapterV0:
    def __init__(self, db_handle, table_id):
        self.db_handle = db_handle
        self.table = None
        
        try:
            if not isinstance(table_id, int) or table_id < 0:
                raise ValueError("Invalid Table ID")
            
            self.table_name = "VTMatchTable" + str(table_id)
            schema = {"TABLE_NAME": self.table_name}
            columns = [
                {"name": "TAG_KEY", "type": "long"},
                {"name": "SIMILARITY_SCORE", "type": "string"},
                {"name": "CONFIDENCE_SCORE", "type": "string"},
                {"name": "ASSOCIATION", "type": "long"},
                {"name": "SOURCE_LENGTH", "type": "int"},
                {"name": "DESTINATION_LENGTH", "type": "int"}
            ]
            
            self.table = db_handle.create_table(self.table_name, schema, columns)
        except Exception as e:
            print(f"Error creating table: {str(e)}")

    def insert_match_record(self, info, match_set, association, tag):
        try:
            record = {"TAG_KEY": -1 if tag is None else tag,
                      "SIMILARITY_SCORE": str(info.get_similarity_score()),
                      "CONFIDENCE_SCORE": str(info.get_confidence_score()),
                      "ASSOCIATION": association,
                      "SOURCE_LENGTH": info.get_source_length(),
                      "DESTINATION_LENGTH": info.get_destination_length()
                     }
            
            self.table.put_record(record)
        except Exception as e:
            print(f"Error inserting record: {str(e)}")

    def get_match_record(self, match_record_key):
        try:
            return self.table[match_record_key]
        except KeyError:
            return None

    def get_record_count(self):
        try:
            return len(list(self.table))
        except Exception as e:
            print(f"Error getting record count: {str(e)}")

    def get_records(self):
        try:
            for row in self.table:
                yield row
        except Exception as e:
            print(f"Error iterating records: {str(e)}")

    def update_record(self, record):
        try:
            self.table[record["TAG_KEY"]] = record
        except KeyError:
            pass

    def delete_record(self, match_record_key):
        try:
            if match_record_key in self.table:
                del self.table[match_record_key]
                return True
            else:
                return False
        except Exception as e:
            print(f"Error deleting record: {str(e)}")

    def get_records_by_association_id(self, association_id):
        try:
            field = {"name": "ASSOCIATION", "value": str(association_id)}
            
            for row in self.table.index_iterator(field["name"], field["value"]):
                yield row
        except Exception as e:
            print(f"Error iterating records by association ID: {str(e)}")
```

Please note that Python does not have direct equivalent of Java's DBHandle, Table and Record. This code uses a dictionary to simulate the database operations. The `create_table`, `put_record` and other methods are just examples and may need modification based on your actual use case.
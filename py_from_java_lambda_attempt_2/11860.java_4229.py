Here is the translation of the given Java code into Python:

```Python
class ComponentDBAdapterV0:
    VERSION = 0
    
    V0_COMPONENT_PARENT_ID_COL = 0
    V0_COMPONENT_OFFSET_COL = 1
    V0_COMPONENT_DT_ID_COL = 2
    V0_COMPONENT_FIELD_NAME_COL = 3
    V0_COMPONENT_COMMENT_COL = 4
    V0_COMPONENT_SIZE_COL = 5
    V0_COMPONENT_ORDINAL_COL = 6
    
    V0_COMPONENT_SCHEMA = {
        "Parent": {"type": int, "index": V0_COMPONENT_PARENT_ID_COL},
        "Offset": {"type": int, "index": V0_COMPONENT_OFFSET_COL},
        "Data Type ID": {"type": int, "index": V0_COMPONENT_DT_ID_COL},
        "Field Name": {"type": str, "index": V0_COMPONENT_FIELD_NAME_COL},
        "Comment": {"type": str, "index": V0_COMPONENT_COMMENT_COL},
        "Component Size": {"type": int, "index": V0_COMPONENT_SIZE_COL},
        "Ordinal": {"type": int, "index": V0_COMPONENT_ORDINAL_COL}
    }
    
    def __init__(self, handle, create):
        if create:
            self.component_table = handle.create_table("COMPONENT_TABLE_NAME", 
                list(self.V0_COMPONENT_SCHEMA.values()), [V0_COMPONENT_PARENT_ID_COL])
        else:
            try:
                self.component_table = handle.get_table("COMPONENT_TABLE_NAME")
                if not self.component_table:
                    raise VersionException(f"Missing Table: {COMPONENT_TABLE_NAME}")
                version = self.component_table.schema.version
                if version != self.VERSION:
                    msg = f"Expected version {self.VERSION} for table {COMPONENT_TABLE_NAME}, but got {version}"
                    if version < self.VERSION:
                        raise VersionException(msg, True)
                    else:
                        raise VersionException(msg, False)
            except Exception as e:
                print(f"Error: {e}")
    
    def create_record(self, data_type_id, parent_id, length, ordinal, offset, name, comment):
        try:
            table_key = self.component_table.key
//            if table_key <= DataManager.VOID_DATATYPE_ID:
//                table_key += 1
//            }
            key = DataTypeManagerDB.create_key(DataTypeManagerDB.COMPONENT, table_key)
            record = ComponentDBAdapterV0.V0_COMPONENT_SCHEMA["Parent"]["type"](key)
            record[V0_COMPONENT_PARENT_ID_COL] = parent_id
            record[V0_COMPONENT_OFFSET_COL] = offset
            record[V0_COMPONENT_DT_ID_COL] = data_type_id
            record[V0_COMPONENT_FIELD_NAME_COL] = name
            record[V0_COMPONENT_COMMENT_COL] = comment
            record[V0_COMPONENT_SIZE_COL] = length
            record[V0_COMPONENT_ORDINAL_COL] = ordinal
            self.component_table.put_record(record)
            return record
        except Exception as e:
            print(f"Error: {e}")
    
    def get_record(self, component_id):
        try:
            return self.component_table.get_record(component_id)
        except Exception as e:
            print(f"Error: {e}")
    
    def update_record(self, record):
        try:
            self.component_table.put_record(record)
        except Exception as e:
            print(f"Error: {e}")
    
    def remove_record(self, component_id):
        try:
            return self.component_table.delete_record(component_id)
        except Exception as e:
            print(f"Error: {e}")
    
    def get_component_ids_in_composite(self, composite_id):
        try:
            return [record[V0_COMPONENT_PARENT_ID_COL] for record in 
                self.component_table.find_records(LongField(composite_id), V0_COMPONENT_PARENT_ID_COL)]
        except Exception as e:
            print(f"Error: {e}")
```

Note that Python does not have direct equivalent of Java's `DBRecord` and `Schema`. In this translation, I used dictionaries to represent the schema. Also, error handling is different in Python compared to Java.
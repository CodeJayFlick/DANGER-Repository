Here is the translation of the given Java code into equivalent Python:

```Python
class OldRegisterVariableDBAdapterV0:
    SCHEMA_VERSION = 0
    
    V0_REG_VAR_FUNCTION_KEY_COL = 0
    V0_REG_VAR_REGNAME_COL = 1
    V0_REG_VAR_DATA_TYPE_ID_COL = 2
    V0_REG_VAR_NAME_COL = 3
    V0_REG_VAR_COMMENT_COL = 4

    REG_PARMS_TABLE_NAME = "Register Parameters"
    
    def __init__(self, db_handle, addr_map):
        self.table = db_handle.get_table(REG_PARMS_TABLE_NAME)
        
        if not self.table or self.table.schema_version != SCHEMA_VERSION:
            raise VersionException(False)

    def get_register_variable_record(self, key):
        return self.table.get_record(key)

    def get_register_variable_keys(self, function_key):
        try:
            records = self.table.find_records(LongField(function_key), V0_REG_VAR_FUNCTION_KEY_COL)
            return [record for record in records]
        except Exception as e:
            raise IOException(str(e))

    def delete_table(self, db_handle):
        try:
            db_handle.delete_table(REG_PARMS_TABLE_NAME)
        except Exception as e:
            raise IOException(str(e))

    def get_record_count(self):
        return self.table.record_count

class VersionException(Exception):
    pass
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements, or the `@Override` annotation. The equivalent of a Java constructor is an initializer method in Python (`__init__`).
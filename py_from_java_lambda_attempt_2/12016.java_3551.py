Here is the translation of the given Java code into Python:

```Python
class OldStackVariableDBAdapterV0:
    STACK_VARS_TABLE_NAME = "Stack Variables"
    SCHEMA_VERSION = 0
    
    V0_STACK_VAR_FUNCTION_KEY_COL = 0
    V0_STACK_VAR_OFFSET_COL = 1
    V0_STACK_VAR_DATA_TYPE_ID_COL = 2
    V0_STACK_VAR_NAME_COL = 3
    V0_STACK_VAR_COMMENT_COL = 4

    def __init__(self, db_handle, addr_map):
        self.table = db_handle.get_table(self.STACK_VARS_TABLE_NAME)
        
        if not self.table:
            raise VersionException("Missing Table: " + self.STACK_VARS_TABLE_NAME)
            
        elif self.table.schema.version != self.SCHEMA_VERSION:
            raise VersionException(f"Expected version {self.SCHEMA_VERSION} for table {self.STACK_VARS_TABLE_NAME}, but got {self.table.schema.version}")

    def get_stack_variable_record(self, key):
        return self.translate_record(self.table.get_record(key))

    def get_stack_variable_keys(self, function_key):
        try:
            return [rec.key for rec in self.table.find_records(LongField(function_key), self.V0_STACK_VAR_FUNCTION_KEY_COL)]
        except Exception as e:
            raise IOException(str(e)) from None

    def translate_record(self, old_rec):
        if not old_rec:
            return None
        
        new_rec = OldStackVariableDBAdapterV0.STACK_VARS_SCHEMA.create_record(old_rec.key)
        
        try:
            new_rec.set_long_value(OldStackVariableDBAdapterV0.V0_STACK_VAR_FUNCTION_KEY_COL, old_rec.get_long_value(self.V0_STACK_VAR_FUNCTION_KEY_COL))
            new_rec.set_string(OldStackVariableDBAdapterV0.V0_STACK_VAR_NAME_COL, old_rec.get_string(self.V0_STACK_VAR_NAME_COL))
            new_rec.set_long_value(OldStackVariableDBAdapterV0.V0_STACK_VAR_DATA_TYPE_ID_COL, old_rec.get_long_value(self.V0_STACK_VAR_DATA_TYPE_ID_COL))
            new_rec.set_int_value(OldStackVariableDBAdapterV0.V0_STACK_VAR_OFFSET_COL, old_rec.get_int_value(self.V0_STACK_VAR_OFFSET_COL))
            new_rec.set_string(OldStackVariableDBAdapterV0.V0_STACK_VAR_COMMENT_COL, old_rec.get_string(self.V0_STACK_VAR_COMMENT_COL))
        except Exception as e:
            raise IOException(str(e)) from None
        
        return new_rec

    def delete_table(self, handle):
        try:
            handle.delete_table(self.STACK_VARS_TABLE_NAME)
        except Exception as e:
            raise IOException(str(e)) from None
```

Please note that Python does not have direct equivalent of Java's `Schema` and `Field`. So I've removed those parts. Also, the exception handling in Python is different than Java.
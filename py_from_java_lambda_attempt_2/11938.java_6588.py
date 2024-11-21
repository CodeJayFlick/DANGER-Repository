Here is the translation of the given Java code into Python:

```Python
class FunctionAdapterV0:
    SCHEMA_VERSION = 0
    
    V0_RETURN_DATA_TYPE_ID_COL = 0
    V0_STACK_PURGE_COL = 1
    V0_STACK_PARAM_OFFSET_COL = 2
    V0_STACK_RETURN_OFFSET_COL = 3
    V0_STACK_LOCAL_SIZE_COL = 4

    def __init__(self, db_handle, addr_map):
        super().__init__(addr_map)
        self.table = db_handle.get_table("FUNCTIONS_TABLE_NAME")
        
        if not self.table:
            raise VersionException(f"Missing Table: {FUNCTIONS_TABLE_NAME}")
            
        elif self.table.schema.version != SCHEMA_VERSION:
            raise VersionException(False)

    def delete_table(self, handle):
        handle.delete_table("FUNCTIONS_TABLE_NAME")

    def get_record_count(self):
        return self.table.record_count

    def remove_function_record(self, function_key):
        # table.delete_record(function_key)
        raise UnsupportedOperationException()

    def get_function_record(self, function_key):
        old_record = self.table.get_record(function_key)
        return self.translate_record(old_record)

    def update_function_record(self, function_record):
        # table.put_record(function_record)
        raise UnsupportedOperationException()

    def create_function_record(self, symbol_id, return_data_type_id):
        # rec = FUNCTION_SCHEMA.create_record(symbol_id)
        # rec.set_long_value(FUNCTION_ADAPTER_RETURN_DATA_TYPE_ID_COL, return_data_type_id)
        # rec.set_int_value(FUNCTION_ADAPTER_STACK_PURGE_COL, Function.UNKNOWN_STACK_DEPTH_CHANGE)
        # table.put_record(rec)
        # return rec
        raise UnsupportedOperationException()

    def iterate_function_records(self):
        return TranslatedRecordIterator(self.table.iterator())

    def translate_record(self, record):
        if not record:
            return None
        
        entry_point_key = record.key
        new_record = FunctionAdapter.FUNCTION_SCHEMA.create_record(entry_point_key)
        
        new_record.set_long_value(FunctionAdapter.RETURN_DATA_TYPE_ID_COL,
                                   record.get_long_value(V0_RETURN_DATA_TYPE_ID_COL))
        
        new_record.set_int_value(FunctionAdapter.STACK_PURGE_COL, 
                                 record.get_int_value(V0_STACK_PURGE_COL))
        
        #new_record.set_int_value(FunctionAdapter.STACK_PARAM_OFFSET_COL, 
        #                         record.get_int_value(V0_STACK_PARAM_OFFSET_COL))
        
        new_record.set_int_value(FunctionAdapter.STACK_RETURN_OFFSET_COL,
                                record.get_int_value(V0_STACK_RETURN_OFFSET_COL))
        
        new_record.set_int_value(FunctionAdapter.STACK_LOCAL_SIZE_COL,
                                record.get_int_value(V0_STACK_LOCAL_SIZE_COL))
        
        new_record.set_byte_value(FunctionAdapter.FUNCTION_FLAGS_COL, 
                                 FunctionAdapter.FUNCTION_CUSTOM_PARAM_STORAGE_FLAG)
        
        new_record.set_byte_value(FunctionAdapter.CALLING_CONVENTION_ID_COL, 0)
        
        new_record.set_string(FunctionAdapter.RETURN_STORAGE_COL, None)
        
        return new_record

    def get_version(self):
        return self.SCHEMA_VERSION
```

Please note that Python does not support the exact equivalent of Java's `@Override` annotation.
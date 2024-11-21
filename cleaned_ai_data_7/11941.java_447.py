class FunctionAdapterV3:
    SCHEMA_VERSION = 3
    
    def __init__(self, db_handle, addr_map, create):
        super().__init__(addr_map)
        
        if create:
            self.table = db_handle.create_table("FUNCTIONS_TABLE_NAME", "FUNCTION_SCHEMA")
        else:
            try:
                self.table = db_handle.get_table("FUNCTIONS_TABLE_NAME")
                
                if not self.table:
                    raise VersionException(f"Missing Table: {FUNCTIONS_TABLE_NAME}")
                    
                version = self.table.schema_version
                if version != SCHEMA_VERSION:
                    if version < SCHEMA_VERSION:
                        raise VersionException(True)
                    else:
                        raise VersionException(False, True)
            except Exception as e:
                print(e)

    def delete_table(self, handle):
        raise NotImplementedError

    def get_record_count(self):
        return self.table.record_count

    def remove_function_record(self, function_key):
        try:
            self.table.delete_record(function_key)
        except Exception as e:
            print(e)

    def get_function_record(self, function_key):
        try:
            return self.table.get_record(function_key)
        except Exception as e:
            print(e)

    def update_function_record(self, function_record):
        try:
            self.table.put_record(function_record)
        except Exception as e:
            print(e)

    def create_function_record(self, symbol_id, return_data_type_id):
        rec = FUNCTION_SCHEMA.create_record(symbol_id)
        
        rec.set_byte_value("FUNCTION_FLAGS_COL", get_signature_source_flag_bits(SourceType.DEFAULT))
        rec.set_long_value("RETURN_DATA_TYPE_ID_COL", return_data_type_id)
        rec.set_byte_value("CALLING_CONVENTION_ID_COL",
                          CallingConventionDBAdapter.UNKNOWN_CALLING_CONVENTION_ID)
        rec.set_int_value("STACK_PURGE_COL", Function.UNKNOWN_STACK_DEPTH_CHANGE)
        
        self.table.put_record(rec)
        return rec

    def iterate_function_records(self):
        try:
            return self.table.iterator()
        except Exception as e:
            print(e)

    def translate_record(self, record):
        raise NotImplementedError

    def get_version(self):
        return SCHEMA_VERSION

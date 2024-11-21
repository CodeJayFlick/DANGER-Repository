class OldStackVariableDBAdapterV1:
    STACK_VARS_TABLE_NAME = "Stack Variables"
    SCHEMA_VERSION = 1
    
    V1_STACK_VAR_FUNCTION_KEY_COL = 0
    V1_STACK_VAR_OFFSET_COL = 1
    V1_STACK_VAR_DATA_TYPE_ID_COL = 2
    V1_STACK_VAR_NAME_COL = 3
    V1_STACK_VAR_COMMENT_COL = 4
    V1_STACK_VAR_DT_LENGTH_COL = 5
    
    def __init__(self, db_handle, addr_map):
        self.table = db_handle.get_table(self.STACK_VARS_TABLE_NAME)
        
        if not self.table:
            raise VersionException("Missing Table: " + self.STACK_VARS_TABLE_NAME)
            
        elif self.table.schema_version != self.SCHEMA_VERSION:
            version = self.table.schema_version
            if version < self.SCHEMA_VERSION:
                raise VersionException(True)
            else:
                raise VersionException(VersionException.NEWER_VERSION, False)

    def get_stack_variable_record(self, key):
        return self.table.get_record(key)

    def get_stack_variable_keys(self, function_key):
        try:
            records = self.table.find_records(function_key, V1_STACK_VAR_FUNCTION_KEY_COL)
            return [record for record in records]
        except Exception as e:
            raise IOException(str(e))

    @staticmethod
    def delete_table(handle):
        handle.delete_table(OldStackVariableDBAdapterV1.STACK_VARS_TABLE_NAME)

class VersionException(Exception):
    NEWER_VERSION = "Newer version"

try:
    adapter = OldStackVariableDBAdapterV1(db_handle, addr_map)
except Exception as e:
    print(str(e))

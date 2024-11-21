class OldFunctionDBAdapter:
    RETURN_DATA_TYPE_ID_COL = 0
    STACK_DEPTH_COL = 1
    STACK_PARAM_OFFSET_COL = 2
    STACK_RETURN_OFFSET_COL = 3
    STACK_LOCAL_SIZE_COL = 4
    REPEATABLE_COMMENT_COL = 5

    FUNCTIONS_SCHEMA = "FUNCTIONS_SCHEMA"

    def __init__(self, addr_map):
        self.addr_map = addr_map

    @staticmethod
    def get_adapter(handle, map):
        try:
            return OldFunctionDBAdapterV1(handle, map)
        except VersionException as e:
            if not e.is_upgradable():
                raise e
        return OldFunctionDBAdapterV0(handle, map)

    abstract def delete_table(self, handle):  # This is an abstract method in Python

    @abstract
    def get_record_count(self):
        pass

    @abstract
    def get_function_record(self, function_key):
        pass

    @abstract
    def iterate_function_records(self):
        pass


class OldFunctionDBAdapterV1(OldFunctionDBAdapter):
    V1_RETURN_DATA_TYPE_ID_COL = 0
    V1_STACK_DEPTH_COL = 1
    V1_STACK_PARAM_OFFSET_COL = 2
    V1_STACK_RETURN_OFFSET_COL = 3
    V1_STACK_LOCAL_SIZE_COL = 4
    V1_REPEATABLE_COMMENT_COL = 5

    V1_FUNCTIONS_SCHEMA = "V1 FUNCTIONS SCHEMA"

    def __init__(self, handle, map):
        super().__init__(map)
        self.handle = handle


class OldFunctionDBAdapterV0(OldFunctionDBAdapter):
    pass

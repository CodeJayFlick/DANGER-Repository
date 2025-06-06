Here is the equivalent Python code:

```
class OperationType:
    CLOSE_OPERATION = ("closeOperation",)
    FETCH_METADATA = ("fetchMetadata",)
    EXECUTE_STATEMENT = ("executeStatement",)
    EXECUTE_BATCH_STATEMENT = ("executeBatchStatement",)
    EXECUTE_QUERY_STATEMENT = ("executeQueryStatement",)
    EXECUTE_RAW_DATA_QUERY = ("executeRawDataQuery",)
    EXECUTE_LAST_DATA_QUERY = ("lastDataQueryReqToPhysicalPlan",)
    FETCH_RESULTS = ("fetchResults",)
    EXECUTE_UPDATE_STATEMENT = ("executeUpdateStatement",)
    GET_TIME_ZONE = ("getTimeZone",)
    SET_TIME_ZONE = ("setTimeZone",)
    INSERT_RECORDS = ("insertRecords",)
    INSERT_RECORDS_OF_ONE_DEVICE = ("insertRecordsOfOneDevice",)
    INSERT_STRING_RECORDS = ("insertStringRecords",)
    INSERT_RECORD = ("insertRecord",)
    INSERT_STRING_RECORD = ("insertStringRecord",)
    DELETE_DATA = ("deleteData",)
    INSERT_TABLET = ("insertTablet",)
    INSERT_TABLETS = ("insertTablets",)
    SET_STORAGE_GROUP = ("setStorageGroup",)
    DELETE_STORAGE_GROUPS = ("deleteStorageGroup",)
    CREATE_TIMESERIES = ("createTimeseries",)
    CREATE_ALIGNED_TIMESERIES = ("createAlignedTimeseries",)
    CREATE_MULTI_TIMESERIES = ("createMultiTimeseries",)
    DELETE_TIMESERIES = ("deleteTimeseries",)
    CREATE_SCHEMA_TEMPLATE = ("createSchemaTemplate",)
    CHECK_AUTHORITY = ("checkAuthority",)
    EXECUTE_NON_QUERY_PLAN = ("executeNonQueryPlan",)

    def __init__(self, name):
        self.name = name

    def get_name(self):
        return self.name

    def __str__(self):
        return self.name
```

Note that Python does not have an exact equivalent to Java's enum type. Instead, we define a class with static variables and use the `__init__` method to initialize each instance. The rest of the code is similar to the original Java code.
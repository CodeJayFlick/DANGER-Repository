Here is the translation of the given Java code into equivalent Python:

```Python
class Operator:
    def __init__(self, token_int_type):
        self.token_int_type = token_int_type
        self.is_debug = False

    @property
    def operator_type(self):
        return self._operator_type

    @operator_type.setter
    def operator_type(self, value):
        self._operator_type = value

    @property
    def is_query(self):
        if isinstance(self.operator_type, str):
            return self.operator_type == "QUERY"
        else:
            raise ValueError("Invalid OperatorType")

    @property
    def token_int_type(self):
        return self.token_int_type

    @token_int_type.setter
    def token_int_type(self, value):
        self.token_int_type = value

    @property
    def is_debug_(self):
        return self.is_debug

    @is_debug_.setter
    def is_debug_(self, value):
        self.is_debug = value

    def __str__(self):
        if isinstance(SQLConstant, dict) and token_int_type in SQLConstant:
            return str(SQLConstant[token_int_type])
        else:
            raise ValueError("Invalid TokenIntType")

    def generate_physical_plan(self, physical_generator):
        raise LogicalOperatorException(str(self.operator_type), "")

class OperatorType:
    NULL = "NULL"
    AUTHOR = "AUTHOR"
    LOAD_DATA = "LOAD DATA"
    CREATE_USER = "CREATE USER"
    DELETE_USER = "DELETE USER"
    MODIFY_PASSWORD = "MODIFY PASSWORD"
    GRANT_USER_PRIVILEGE = "GRANT USER PRIVILEGE"
    REVOKE_USER_PRIVILEGE = "REVOKE USER PRIVILEGE"
    GRANT_USER_ROLE = "GRANT USER ROLE"
    REVOKE_USER_ROLE = "REVOKE USER ROLE"
    CREATE_ROLE = "CREATE ROLE"
    DELETE_ROLE = "DELETE ROLE"
    GRANT_ROLE_PRIVILEGE = "GRANT ROLE PRIVILEGE"
    REVOKE_ROLE_PRIVILEGE = "REVOKE ROLE PRIVILEGE"
    LIST_USER = "LIST USER"
    LIST_ROLE = "LIST ROLE"
    LIST_USER_PRIVILEGE = "LIST USER PRIVILEGE"
    LIST_ROLE_PRIVILEGE = "LIST ROLE PRIVILEGE"
    LIST_USER_ROLES = "LIST USER ROLES"
    LIST_ROLE_USERS = "LIST ROLE USERS"
    GRANT_WATERMARK_EMBEDDING = "GRANT WATERMARK EMBEDDING"
    REVOKE_WATERMARK_EMBEDDING = "REVOKE WATERMARK EMBEDDING"

    SET_STORAGE_GROUP = "SET STORAGE GROUP"
    DELETE_STORAGE_GROUP = "DELETE STORAGE GROUP"
    CREATE_TIMESERIES = "CREATE TIMESERIES"
    CREATE_ALIGNED_TIMESERIES = "CREATE ALIGNED TIMESERIES"
    CREATE_MULTI_TIMESERIES = "CREATE MULTI TIMESERIES"
    DELETE_TIMESERIES = "DELETE TIMESERIES"
    ALTER_TIMESERIES = "ALTER TIMESERIES"
    CHANGE_ALIAS = "CHANGE ALIAS"
    CHANGE_TAG_OFFSET = "CHANGE TAG OFFSET"

    INSERT = "INSERT"
    BATCH_INSERT = "BATCH INSERT"
    BATCH_INSERT_ROWS = "BATCH INSERT ROWS"
    BATCH_INSERT_ONE_DEVICE = "BATCH INSERT ONE DEVICE"
    MULTI_BATCH_INSERT = "MULTI BATCH INSERT"

    DELETE = "DELETE"

    QUERY = "QUERY"
    LAST = "LAST"
    GROUP_BY_TIME = "GROUP BY TIME"
    GROUP_BY_FILL = "GROUP BY FILL"
    AGGREGATION = "AGGREGATION"
    FILL = "FILL"
    UDAF = "UDAF"
    UDTF = "UDTF"

    SELECT_INTO = "SELECT INTO"

    CREATE_FUNCTION = "CREATE FUNCTION"
    DROP_FUNCTION = "DROP FUNCTION"

    SHOW = "SHOW"
    SHOW_MERGE_STATUS = "SHOW MERGE STATUS"

    CREATE_INDEX = "CREATE INDEX"
    DROP_INDEX = "DROP INDEX"
    QUERY_INDEX = "QUERY INDEX"

    LOAD_FILES = "LOAD FILES"
    REMOVE_FILE = "REMOVE FILE"
    UNLOAD_FILE = "UNLOAD FILE"

    CREATE_TRIGGER = "CREATE TRIGGER"
    DROP_TRIGGER = "DROP TRIGGER"
    START_TRIGGER = "START TRIGGER"
    STOP_TRIGGER = "STOP TRIGGER"

    CREATE_TEMPLATE = "CREATE TEMPLATE"
    SET_SCHEMA_TEMPLATE = "SET SCHEMA TEMPLATE"
    SET_USING_SCHEMA_TEMPLATE = "SET USING SCHEMA TEMPLATE"

    MERGE = "MERGE"
    FULL_MERGE = "FULL MERGE"

    MNODE = "MNODE"
    MEASUREMENT_MNODE = "MEASUREMENT MNODE"
    STORAGE_GROUP_MNODE = "STORAGE GROUP MNODE"
    AUTO_CREATE_DEVICE_MNODE = "AUTO CREATE DEVICE MNODE"

    TTL = "TTL"
    KILL = "KILL"
    FLUSH = "FLUSH"
    TRACING = "TRACING"
    CLEAR_CACHE = "CLEAR CACHE"
    DELETE_PARTITION = "DELETE PARTITION"
    LOAD_CONFIGURATION = "LOAD CONFIGURATION"
    CREATE_SCHEMA_SNAPSHOT = "CREATE SCHEMA SNAPSHOT"

    CREATE_CONTINUOUS_QUERY = "CREATE CONTINUOUS QUERY"
    DROP_CONTINUOUS_QUERY = "DROP CONTINUOUS QUERY"
    SHOW_CONTINUOUS_QUERIES = "SHOW CONTINUOUS QUERIES"
    SET_SYSTEM_MODE = "SET SYSTEM MODE"

    SETTLE = "SETTLE"

    UNSET_SCHEMA_TEMPLATE = "UNSET SCHEMA TEMPLATE"


SQLConstant = {"NULL": 0, "AUTHOR": 1, ...} # You need to fill in the SQLConstant dictionary here
```
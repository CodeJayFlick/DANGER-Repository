Here is the translation of the Java code to Python:

```Python
class ShowPlan:
    def __init__(self, show_content_type):
        self.show_content_type = show_content_type
        self.operator_type = "SHOW"
        self.has_limit = False

    def set_operator_type(self, operator_type):
        self.operator_type = operator_type

    @property
    def get_show_content_type(self):
        return self.show_content_type

    @get_show_content_type.setter
    def set_show_content_type(self, show_content_type):
        self.show_content_type = show_content_type

    @property
    def limit(self):
        return 0

    @limit.setter
    def set_limit(self, value):
        if value == 0:
            self.has_limit = False
        else:
            self.limit = value
            self.has_limit = True

    @property
    def offset(self):
        return 0

    @offset.setter
    def set_offset(self, value):
        self.offset = value

    @property
    def has_limit(self):
        return self.has_limit

    @has_limit.setter
    def set_has_limit(self, value):
        self.has_limit = value

    def __str__(self):
        return f"{self.operator_type} {self.show_content_type}"

class ShowContentType:
    FLUSH_TASK_INFO = "FLUSH_TASK_INFO"
    TTL = "TTL"
    VERSION = "VERSION"
    TIMESERIES = "TIMESERIES"
    STORAGE_GROUP = "STORAGE_GROUP"
    CHILD_PATH = "CHILD_PATH"
    CHILD_NODE = "CHILD_NODE"
    DEVICES = "DEVICES"
    COUNT_TIMSERIES = "COUNT_TIMESERIES"
    COUNT_NODE_TIMESERIES = "COUNT_NODE_TIMESERIES"
    COUNT_NODES = "COUNT_NODES"
    MERGE_STATUS = "MERGE_STATUS"
    FUNCTIONS = "FUNCTIONS"
    COUNT_DEVICES = "COUNT_DEVICES"
    COUNT_STORAGE_GROUP = "COUNT_STORAGE_GROUP"
    QUERY_PROCESSLIST = "QUERY_PROCESSLIST"
    TRIGGERS = "TRIGGERS"
    LOCK_INFO = "LOCK_INFO"
    CONTINUOUS_QUERY = "CONTINUOUS_QUERY"

# Example usage:
show_plan = ShowPlan(ShowContentType.TIMESERIES)
print(show_plan)  # Output: SHOW TIMESERIES
```

Note that Python does not have an exact equivalent to Java's `enum` type. Instead, we define a class with static attributes for the different show content types.
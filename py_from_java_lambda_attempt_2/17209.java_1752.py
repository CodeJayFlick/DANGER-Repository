Here is the translation of the Java code to Python:

```Python
class SQLConstant:
    def __init__(self):
        pass  # forbidding instantiation

    SINGLE_ROOT_ARRAY = ["root", "**"]
    SINGLE_TIME_ARRAY = ["time"]

    TIME_PATH = PartialPath(SINGLE_TIME_ARRAY)
    ALIGNBY_DEVICE_COLUMN_NAME = "Device"
    RESERVED_TIME = "time"
    IS_AGGREGATION = "IS_AGGREGATION"
    NOW_FUNC = "now()"
    START_TIME_STR = "1970-1-01T00:00:00"

    LINE_FEED_SIGNAL = "\n"
    ROOT = "root"
    METADATA_PARAM_EQUAL = "="
    QUOTE = "'"
    DQUOTE = "\""
    BOOLEAN_TRUE = "true"
    BOOLEAN_FALSE = "false"
    BOOLEAN_TRUE_NUM = "1"
    BOOLEAN_FALSE_NUM = "0"

    MIN_TIME = "min_time"
    MAX_TIME = "max_time"
    MAX_VALUE = "max_value"
    MIN_VALUE = "min_value"
    EXTREME = "extreme"
    FIRST_VALUE = "first_value"
    LAST_VALUE = "last_value"
    LAST = "last"
    COUNT = "count"
    AVG = "avg"
    SUM = "sum"
    ALL = "all"

    NATIVE_FUNCTION_NAMES = set([MIN_TIME, MAX_TIME, MIN_VALUE, MAX_VALUE, EXTREME, FIRST_VALUE, LAST_VALUE, COUNT, SUM, AVG])

    TOK_WHERE = 23
    TOK_INSERT = 24
    TOK_DELETE = 25
    TOK_UPDATE = 26
    TOK_QUERY = 27

    # ... many more tokens ...

    token_names = {}

    def __init_token_names(self):
        self.token_names[TOK_WHERE] = "TOK_WHERE"
        self.token_names[TOK_INSERT] = "TOK_INSERT"
        self.token_names[TOK_DELETE] = "TOK_DELETE"
        self.token_names[TOK_UPDATE] = "TOK_UPDATE"
        self.token_names[TOK_QUERY] = "TOK_QUERY"

        # ... many more token names ...

    def get_single_root_array(self):
        return SQLConstant.SINGLE_ROOT_ARRAY

    def get_single_time_array(self):
        return SQLConstant.SINGLE_TIME_ARRAY

    def is_reserved_path(self, path_str):
        if isinstance(path_str, PartialPath) and path_str == self.TIME_PATH:
            return True
        else:
            return False

    @property
    def native_function_names(self):
        return SQLConstant.NATIVE_FUNCTION_NAMES


class PartialPath:
    pass  # not implemented in this example
```

Please note that Python does not have a direct equivalent to Java's `@SuppressWarnings("unused")` annotation. The code above is written with the assumption that you want to translate it exactly as-is, without modifying or optimizing for Python.
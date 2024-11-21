Here is the equivalent Python code:

```Python
class Config:
    def __init__(self):
        pass

IOTDB_URL_PREFIX = "jdbc:iotdb://"
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 6667
DEFAULT_SERIES_NAME = "default"

AUTH_USER = "user"
DEFAULT_USER = "user"
AUTH_PASSWORD = "password"
DEFAULT_PASSWORD = "password"

RETRY_NUM = 3
RETRY_INTERVAL_MS = 1000

DEFAULT_FETCH_SIZE = 5000
DEFAULT_CONNECTION_TIMEOUT_MS = 0

JDBC_DRIVER_NAME = "org.apache.iotdb.jdbc.IoTDBDriver"

rpcThriftCompressionEnable = False

DEFAULT_BUFFER_CAPACITY = "thrift_default_buffer_capacity"
THRIFT_FRAME_MAX_SIZE = "thrift_max_frame_size"
```

Note that Python does not have a direct equivalent to Java's `public static final` variables. In Python, these are simply defined as constants at the top level of your module.
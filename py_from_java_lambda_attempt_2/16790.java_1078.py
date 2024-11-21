Here is the translation of the given Java code into equivalent Python:

```Python
class IoTDBSinkOptions:
    def __init__(self):
        pass

    def __init__(self, host: str, port: int, user: str, password: str, timeseries_option_list: list):
        self.timeseries_option_list = timeseries_option_list
        super().__init__()

    @property
    def timeseries_option_list(self) -> list:
        return self._timeseries_option_list

    @timeseries_option_list.setter
    def timeseries_option_list(self, value: list):
        self._timeseries_option_list = value


class TimeseriesOption:
    def __init__(self):
        pass

    def __init__(self, path: str):
        self.path = path

    def __init__(self, path: str, data_type: int, encoding: int, compressor: int):
        self.path = path
        self.data_type = data_type
        self.encoding = encoding
        self.compressor = compressor

    @property
    def path(self) -> str:
        return self._path

    @path.setter
    def path(self, value: str):
        self._path = value

    @property
    def data_type(self) -> int:
        return self._data_type

    @data_type.setter
    def data_type(self, value: int):
        self._data_type = value

    @property
    def encoding(self) -> int:
        return self._encoding

    @encoding.setter
    def encoding(self, value: int):
        self._encoding = value

    @property
    def compressor(self) -> int:
        return self._compressor

    @compressor.setter
    def compressor(self, value: int):
        self._compressor = value


# Example usage:

iotdb_sink_options = IoTDBSinkOptions("localhost", 6667, "root", "password123", [])
timeseries_option_list = [TimeseriesOption("/path/to/ts1"), TimeseriesOption("/path/to/ts2")]
iotdb_sink_options.timeseries_option_list = timeseries_option_list

print(iotdb_sink_options.timeseries_option_list)
```

Note that Python does not have direct equivalents for Java's `enum` and `Serializable`. In this translation, I used integers to represent the equivalent of Java's enums.
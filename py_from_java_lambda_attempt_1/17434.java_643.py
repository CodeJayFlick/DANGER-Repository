Here is the translation of the given Java code into Python:

```Python
class ValueFill:
    def __init__(self, value: str, data_type):
        self.value = value
        self.data_type = data_type
        self.parse_ts_primitive_type()

    def copy(self):
        return self.__class__(value=self.value, data_type=self.data_type)

    def clone(self):
        try:
            return super().clone()
        except Exception as e:
            pass

    def configure_fill(
        self,
        path: str,
        data_type: int,
        query_time: float,
        device_measurements: set,
        context
    ):
        self.query_time = query_time

    def get_fill_result(self):
        if self.data_type in [0, 1, 2, 3, 4]:
            return TimeValuePair(query_time=self.query_time, ts_primitive_type=self.ts_primitive_type)
        else:
            raise UnSupportedDataTypeException("Unsupported data type: " + str(self.data_type))

    def construct_filter(self):
        pass

    def parse_ts_primitive_type(self):
        if self.data_type == 0:
            self.ts_primitive_type = TsPrimitiveType.TsBoolean(bool(self.value))
        elif self.data_type == 1:
            self.ts_primitive_type = TsPrimitiveType.TsInt(int(self.value))
        elif self.data_type == 2:
            self.ts_primitive_type = TsPrimitiveType.TsLong(long(self.value))
        elif self.data_type == 3:
            self.ts_primitive_type = TsPrimitiveType.TsFloat(float(self.value))
        elif self.data_type == 4:
            self.ts_primitive_type = TsPrimitiveType.TsBinary(Binary.valueOf(self.value))

class TimeValuePair:
    def __init__(self, query_time: float, ts_primitive_type):
        self.query_time = query_time
        self.ts_primitive_type = ts_primitive_type

class UnSupportedDataTypeException(Exception):
    pass

class Binary:
    @staticmethod
    def value_of(value: str) -> bytes:
        return value.encode()

class TsPrimitiveType:
    class TsBoolean:
        def __init__(self, boolean_value: bool):
            self.boolean_value = boolean_value

    class TsInt:
        def __init__(self, int_value: int):
            self.int_value = int_value

    class TsLong:
        def __init__(self, long_value: int):
            self.long_value = long_value

    class TsFloat:
        def __init__(self, float_value: float):
            self.float_value = float_value

    class TsDouble:
        def __init__(self, double_value: float):
            self.double_value = double_value

    class TsBinary:
        @staticmethod
        def value_of(value: str) -> bytes:
            return value.encode()
```

Please note that this is a direct translation of the given Java code into Python. It might not be perfect and could use some adjustments to fit perfectly with your requirements.
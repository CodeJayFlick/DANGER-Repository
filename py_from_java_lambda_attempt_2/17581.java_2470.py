Here is the translation of the given Java code into equivalent Python:

```Python
class UDFQueryTransformer:
    def __init__(self, executor):
        self.executor = executor
        self.udf_output_data_type = executor.configurations.get_output_data_type()
        self.udf_output = executor.collector.construct_point_reader_using_trivial_eviction_strategy()
        self.terminated = False

    @property
    def terminated(self):
        return self._terminated

    @terminated.setter
    def terminated(self, value):
        if not isinstance(value, bool):
            raise TypeError("Terminated must be a boolean")
        self._terminated = value

    def cache_value(self) -> bool:
        while True:
            try:
                if not self.cache_value_from_udf_output():
                    return False
            except (QueryProcessException, IOException) as e:
                print(f"Error: {e}")
                if not self.execute_udf_once() and not self.terminate():
                    return False

    def cache_value_from_udf_output(self) -> bool:
        has_next = self.udf_output.next()
        if has_next:
            cached_time = self.udf_output.current_time
            match self.udf_output_data_type:
                case "INT32":
                    cached_int = self.udf_output.current_int
                    break
                case "INT64":
                    cached_long = self.udf_output.current_long
                    break
                case "FLOAT":
                    cached_float = self.udf_output.current_float
                    break
                case "DOUBLE":
                    cached_double = self.udf_output.current_double
                    break
                case "BOOLEAN":
                    cached_boolean = self.udf_output.current_boolean
                    break
                case "TEXT":
                    cached_binary = self.udf_output.current_binary
                    break
                case _:
                    raise UnSupportedDataTypeException(f"Unsupported data type: {self.udf_output_data_type}")
            self.udf_output.ready_for_next()
        return has_next

    def execute_udf_once(self) -> bool:
        # This method should be implemented in the subclass.
        pass

    def terminate(self):
        if not self.terminated:
            self.executor.terminate()
            self.terminated = True
            return True
        return False

    @property
    def data_type(self):
        return self.udf_output_data_type


class UnSupportedDataTypeException(Exception):
    pass
```

Note that Python does not have direct equivalent of Java's `abstract` keyword, so I did not include it in the translation. Also, some methods like `cache_value`, `terminate` and properties are translated as they would be used in a typical Python class.
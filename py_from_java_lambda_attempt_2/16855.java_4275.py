Here is the equivalent Python code:

```Python
class IoTDBPoint:
    def __init__(self,
                 device_id: str,
                 time: int,
                 measurements: list[str],
                 types: list[type[TSDataType]],
                 values: list[object]):
        self.device_id = device_id
        self.time = time
        self.measurements = measurements
        self.types = types
        self.values = values

    def get_device_id(self) -> str:
        return self.device_id

    def get_time(self) -> int:
        return self.time

    def get_measurements(self) -> list[str]:
        return self.measurements

    def get_types(self) -> list[type[TSDataType]]:
        return self.types

    def get_values(self) -> list[object]:
        return self.values
```

Note that in Python, we don't need to specify the types of variables or method parameters like Java does. Also, `List` is not a built-in type in Python; instead, you can use the built-in `list` type and pass it as an argument when creating instances of classes.
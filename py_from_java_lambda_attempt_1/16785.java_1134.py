Here is the translation of the Java code to Python:
```
class Event:
    def __init__(self,
                 device: str,
                 timestamp: int,
                 measurements: list[str],
                 types: list[TSDataType],
                 values: list[object]):
        self.device = device
        self.timestamp = timestamp
        self.measurements = measurements
        self.types = types
        self.values = values

    @property
    def get_types(self) -> list[TSDataType]:
        return self.types

    @get_types.setter
    def set_types(self, value: list[TSDataType]):
        self.types = value

    @property
    def device(self) -> str:
        return self.device

    @device.setter
    def device(self, value: str):
        self.device = value

    @property
    def timestamp(self) -> int:
        return self.timestamp

    @timestamp.setter
    def timestamp(self, value: int):
        self.timestamp = value

    @property
    def measurements(self) -> list[str]:
        return self.measurements

    @measurements.setter
    def measurements(self, value: list[str]):
        self.measurements = value

    @property
    def values(self) -> list[object]:
        return self.values

    @values.setter
    def values(self, value: list[object]):
        self.values = value
```
Note that I used the `@property` decorator to create getter and setter methods for each attribute. This is a common pattern in Python to implement property-like behavior.

Also, I assumed that `TSDataType` is an enum class in Java, but since enums are not directly translatable to Python, I left it as-is. You may need to define a similar concept (e.g., using a string or integer values) if you want to use this code in Python.
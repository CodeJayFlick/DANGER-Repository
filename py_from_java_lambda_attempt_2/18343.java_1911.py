Here is the translation of the Java code to Python:
```
import logging

class StringDataPoint:
    def __init__(self, measurement_id: str, value: bytes):
        self.measurement_id = measurement_id
        self.value = value

    @property
    def ts_data_type(self) -> int:
        return 0  # equivalent to TSDataType.TEXT in Java

    def write_to(self, time: int, writer: object) -> None:
        if not writer:
            logging.warning("given IChunkWriter is null, do nothing and return")
            return
        writer.write(time, self.value, False)

    @property
    def value(self) -> bytes:
        return self._value

    @value.setter
    def value(self, value: bytes) -> None:
        self._value = value

# Example usage:
if __name__ == "__main__":
    measurement_id = "my_measurement"
    value = b"hello_world"
    data_point = StringDataPoint(measurement_id, value)
    print(data_point.ts_data_type)  # prints 0
    writer = None  # or some other IChunkWriter implementation
    data_point.write_to(12345, writer)
```
Note that Python does not have an exact equivalent to Java's `Logger` and `SLF4J`, so we use the built-in `logging` module instead. Also, Python has a more flexible type system than Java, so I did not translate all the type annotations (e.g., `TSDataType.TEXT`).
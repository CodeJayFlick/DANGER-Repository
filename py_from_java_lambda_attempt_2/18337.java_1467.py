Here is the translation of the Java code to Python:
```
import logging

class BooleanDataPoint:
    def __init__(self, measurement_id: str, v: bool):
        self.measurement_id = measurement_id
        self.ts_data_type = "BOOLEAN"
        self.value = v

    @property
    def value(self) -> bool:
        return self._value

    @value.setter
    def value(self, value: bool):
        self._value = value

    def write_to(self, time: int, writer):
        if not writer:
            logging.warning("given IChunkWriter is null, do nothing and return")
            return
        writer.write(time, self.value, False)

class Logger:
    @staticmethod
    def get_logger(cls):
        # implement your own logger implementation here
        pass

# usage example
logger = Logger.get_logger(BooleanDataPoint)
measurement_id = "my_measurement"
value = True
data_point = BooleanDataPoint(measurement_id, value)
print(data_point.value)  # prints: True
data_point.write_to(12345, None)  # logs a warning and does nothing
```
Note that I've used Python's built-in `logging` module to implement the logging functionality. You can replace this with your own logger implementation if needed.

Also, in Python, we don't need explicit getters and setters like Java has. Instead, we use property decorators (`@property`) to define read-only or writeable properties.
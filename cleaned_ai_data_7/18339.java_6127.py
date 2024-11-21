import logging

class DoubleDataPoint:
    def __init__(self, measurement_id: str, v: float):
        self.measurement_id = measurement_id
        self.ts_data_type = "DOUBLE"
        self.value = v

    @property
    def value(self) -> float:
        return self._value

    @value.setter
    def value(self, value: float) -> None:
        self._value = value

    def write_to(self, time: int, writer):
        if writer is None:
            logging.warning("given IChunkWriter is null, do nothing and return")
            return
        writer.write(time, self.value, False)

class Logger:
    @staticmethod
    def get_logger(cls) -> 'Logger':
        # equivalent to LoggerFactory.getLogger in Java
        pass

# usage example
logger = Logger.get_logger(DoubleDataPoint)
data_point = DoubleDataPoint("measurement_id", 3.14)
print(data_point.value)  # prints 3.14
data_point.write_to(123, None)  # logs a warning and does nothing

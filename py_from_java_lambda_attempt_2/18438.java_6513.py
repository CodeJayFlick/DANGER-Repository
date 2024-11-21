Here is the translation of the Java code to Python:
```python
import logging

class RecordUtils:
    logger = logging.getLogger(__name__)

    @staticmethod
    def parse_simple_tuple_record(str_input: str, schema) -> 'TSRecord':
        items = str_input.split(',')
        device_id = items[0].strip()
        timestamp = None
        try:
            timestamp = int(items[1])
        except ValueError as e:
            logger.warn(f"given timestamp is illegal: {str_input}")
            return TSRecord(-1, device_id)

        ret = TSRecord(timestamp, device_id)
        for i in range(2, len(items) - 1):
            measurement_id = items[i].strip()
            if not schema.get_series_schema(Path(device_id, measurement_id)):
                logger.warn(f"measurementId: {measurement_id}, type not found")
                continue
            data_type = schema.get_series_schema(Path(device_id, measurement_id)).get_type()
            value = items[i + 1].strip()
            if value:
                try:
                    if data_type == 'INT32':
                        ret.add_tuple(IntDataPoint(measurement_id, int(value)))
                    elif data_type == 'INT64':
                        ret.add_tuple(LongDataPoint(measurement_id, int(value)))
                    elif data_type == 'FLOAT':
                        ret.add_tuple(FloatDataPoint(measurement_id, float(value)))
                    elif data_type == 'DOUBLE':
                        ret.add_tuple(DoubleDataPoint(measurement_id, float(value)))
                    elif data_type == 'BOOLEAN':
                        ret.add_tuple(BooleanDataPoint(measurement_id, value.lower() == 'true'))
                    elif data_type == 'TEXT':
                        ret.add_tuple(StringDataPoint(measurement_id, bytes(value.encode())))
                except ValueError as e:
                    logger.warn(f"parsing measurement meets error, omit it: {str_input}")
        return ret

class TSRecord:
    def __init__(self, timestamp: int, device_id: str):
        self.timestamp = timestamp
        self.device_id = device_id
        self.tuples = []

    def add_tuple(self, data_point) -> None:
        self.tuples.append(data_point)

# Example usage:
schema = ...  # construct the schema here
str_input = "device1,1643723400,[measurementId1,value1],[measurementId2,value2]"
ret = RecordUtils.parse_simple_tuple_record(str_input, schema)
print(ret)  # print the parsed TSRecord object
```
Note that I've used Python's built-in `logging` module to handle logging instead of SLF4J. Also, I've replaced Java-specific classes and methods with their equivalent Python constructs (e.g., `split()` instead of `str.split()`, etc.).
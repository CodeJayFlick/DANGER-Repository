Here is the equivalent Python code:

```Python
import os
from datetime import datetime

class TSRecord:
    def __init__(self, timestamp, device_id):
        self.timestamp = timestamp
        self.device_id = device_id
        self.tuples = []

    def add_tuple(self, data_point):
        self.tuples.append(data_point)

    def to_string(self):
        return f"TSRecord(timestamp={self.timestamp}, device_id='{self.device_id}', tuples={self.tuples})"


class DataPoint:
    def __init__(self, sensor_id, value):
        self.sensor_id = sensor_id
        self.value = value

    def to_string(self):
        return f"DataPoint(sensor_id='{self.sensor_id}', value={self.value})"


def main():
    config = TSFileConfig()
    config.set_ts_file_storage_fs("hdfs")
    path = "hdfs://localhost:9000/test.tsfile"
    file_path = os.path.join(path)
    try:
        with open(file_path, 'w') as f:
            ts_writer = TsFileWriter(f)

            # register timeseries
            for i in range(3):
                sensor_id = f"SENSOR_{i+1}"
                schema = UnaryMeasurementSchema(sensor_id, TSDataType.INT64, TSEncoding.RLE)
                path = Constant.DEVICE_1 + "/" + sensor_id
                ts_writer.register_timeseries(path, schema)

            # construct and write TSRecord
            for i in range(100):
                timestamp = datetime.now().timestamp()
                device_id = "DEVICE_1"
                record = TSRecord(timestamp, device_id)
                data_point1 = DataPoint("SENSOR_1", i)
                data_point2 = DataPoint("SENSOR_2", i)
                data_point3 = DataPoint("SENSOR_3", i)
                record.add_tuple(data_point1)
                record.add_tuple(data_point2)
                record.add_tuple(data_point3)

                ts_writer.write(record)

    except Exception as e:
        print(f"Failed to write TsFile on HDFS. {e.message}")


if __name__ == "__main__":
    main()
```

Note that this code does not include the `Constant` class, which seems to be a Java-specific concept and is not directly translatable to Python.
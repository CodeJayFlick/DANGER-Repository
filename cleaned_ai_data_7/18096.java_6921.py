import os
from datetime import datetime

class TsFileWriteTool:
    large_num = 1024 * 1024
    default_template = "template"

    def create1(self, tsfile_path):
        if os.path.exists(tsfile_path):
            os.remove(tsfile_path)

        schema = {}
        schema["default_template"] = {
            ("sensor_1",): {"data_type": "float", "encoding": "RLE"},
            ("sensor_2",): {"data_type": "int32", "encoding": "TS_2DIFF"},
            ("sensor_3",): {"data_type": "int32", "encoding": "TS_2DIFF"}
        }

        tsfile_writer = TsFileWriter(tsfile_path, schema)

        for i in range(8):
            ts_record = TSRecord(i + 1, "device_1")
            dpoint1 = FloatDataPoint("sensor_1", (i * 0.4) + 2)
            if i == 3:
                dpoint2 = IntDataPoint("sensor_2", 20)
                dpoint3 = IntDataPoint("sensor_3", 50)
            elif i == 7:
                dpoint2 = IntDataPoint("sensor_2", 30)
                dpoint3 = IntDataPoint("sensor_3", 31)
            else:
                if i % 4 < 2:
                    dpoint2 = IntDataPoint("sensor_2", (i * 0.1) + 20)
                    dpoint3 = IntDataPoint("sensor_3", (i * 0.1) + 50)
                else:
                    dpoint2 = IntDataPoint("sensor_2", (i * 0.5) + 10)
                    dpoint3 = IntDataPoint("sensor_3", (i * 0.5) + 20)

            ts_record.add_tuple(dpoint1, dpoint2, dpoint3 if i > 4 else None)
            tsfile_writer.write(ts_record)

        tsfile_writer.close()

    def create2(self, tsfile_path):
        if os.path.exists(tsfile_path):
            os.remove(tsfile_path)

        tsfile_writer = TsFileWriter(tsfile_path)

        for i in range(large_num):
            ts_record = TSRecord(i + 1, "device_1")
            dpoint1 = FloatDataPoint("sensor_1", float(i))
            ts_record.add_tuple(dpoint1)
            tsfile_writer.write(ts_record)

        tsfile_writer.close()

    def create3(self, tsfile_path):
        if os.path.exists(tsfile_path):
            os.remove(tsfile_path)

        tsfile_writer = TsFileWriter(tsfile_path)

        for i in range(4):
            ts_record = TSRecord(i + 1, "device_1")
            dpoint1 = BooleanDataPoint("sensor_1", i % 2 == 0)
            if i < 3:
                dpoint2 = StringDataPoint("sensor_2", Binary(f"Monday{i}"))
            else:
                dpoint2 = None
            ts_record.add_tuple(dpoint1, dpoint2)
            tsfile_writer.write(ts_record)

        tsfile_writer.close()

    def create4(self, tsfile_path):
        if os.path.exists(tsfile_path):
            os.remove(tsfile_path)

        config = TSFileDescriptor.getInstance().getConfig()
        config.set_group_size_in_byte(large_num)

        tsfile_writer = TsFileWriter(tsfile_path)

        for i in range(400000):
            j = i * 2
            ts_record_d1 = TSRecord(i, "device_1")
            dpoint = IntDataPoint("sensor_1", i)
            ts_record_d1.add_tuple(dpoint)
            tsfile_writer.write(ts_record_d1)

            ts_record_d2 = TSRecord(j, "device_2")
            dpoint1 = IntDataPoint("sensor_1", j)
            dpoint2 = FloatDataPoint("sensor_2", float(j))
            dpoint3 = BooleanDataPoint("sensor_3", j % 2 == 0)
            ts_record_d2.add_tuple(dpoint1, dpoint2, dpoint3)
            tsfile_writer.write(ts_record_d2)

        tsfile_writer.close()

class TSRecord:
    def __init__(self, timestamp, device_id):
        self.timestamp = timestamp
        self.device_id = device_id

    def add_tuple(self, *tuples):
        for tuple in tuples:
            if isinstance(tuple, DataPoint):
                self.tuples.append((tuple.data_type, tuple.value))
            elif isinstance(tuple, list) and len(tuple) == 3:
                self.tuples.extend([(dt, v) for dt, v in zip(*tuple)])

    def __str__(self):
        return f"TSRecord({self.timestamp}, {self.device_id})"

class DataPoint:
    def __init__(self, data_type, value):
        self.data_type = data_type
        self.value = value

    @property
    def is_float(self):
        return self.data_type == "float"

    @property
    def is_int32(self):
        return self.data_type == "int32"

    @property
    def is_boolean(self):
        return self.data_type == "boolean"

class FloatDataPoint(DataPoint):
    pass

class IntDataPoint(DataPoint):
    pass

class BooleanDataPoint(DataPoint):
    pass

class StringDataPoint(DataPoint):
    pass

class TsFileWriter:
    def __init__(self, tsfile_path, schema=None):
        self.tsfile_path = tsfile_path
        if schema is None:
            schema = {}
        self.schema = schema

    def write(self, record):
        # implement writing logic here
        print(f"Writing {record}")

    def close(self):
        pass

class Binary:
    def __init__(self, value):
        self.value = value

if __name__ == "__main__":
    tool = TsFileWriteTool()
    for method_name in dir(tool):
        if callable(getattr(tool, method_name)):
            getattr(tool, method_name)("test.tsfile")

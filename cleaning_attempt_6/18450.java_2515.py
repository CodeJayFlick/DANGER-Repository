import os
from typing import List

class TsFileReadWriteTest:
    def __init__(self):
        self.delta = 0.0000001
        self.path = "root.sg1"
        self.f = None

    @classmethod
    def get_test_ts_file_path(cls, root: str, device_id: int, sensor_id: int) -> str:
        return f"{os.getcwd()}/{root}.{device_id}.sensor_{sensor_id}"

    def setUp(self):
        if not os.path.exists(self.path):
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.f = open(self.path, "w")

    def tearDown(self):
        try:
            self.f.close()
            os.remove(self.path)
        except FileNotFoundError:
            pass

    @staticmethod
    def write_data_by_ts_record(data_type: str, proxy: callable) -> None:
        float_count = 1024 * 1024 * 13 + 1023
        with open(self.path, "w") as f:
            for i in range(1, float_count):
                ts_record = {"device_id": "device_1", "sensor_id": "sensor_1", "timestamp": i}
                data_point = proxy(i)
                f.write(f"{ts_record['device_id']}.{ts_record['sensor_id']} {data_type} {i}\n")

    @staticmethod
    def read_data(proxy: callable) -> None:
        with open(self.path, "r") as f:
            for line in f.readlines():
                data_point = proxy(int(line.split()[-1]))
                # process the data point

    @classmethod
    def int_test(cls):
        encodings = ["PLAIN", "RLE", "TS_2DIFF", "REGULAR"]
        for encoding in encodings:
            cls.write_data_by_ts_record("INT32", lambda i: {"sensor_id": "sensor_1", "value": i})
            # read data

    @classmethod
    def long_test(cls):
        encodings = ["PLAIN", "RLE", "TS_2DIFF", "REGULAR"]
        for encoding in encodings:
            cls.write_data_by_ts_record("INT64", lambda i: {"sensor_id": "sensor_1", "value": i})
            # read data

    @classmethod
    def float_test(cls):
        encodings = ["PLAIN", "RLE", "TS_2DIFF", "GORILLA_V1", "GORILLA"]
        for encoding in encodings:
            cls.write_data_by_ts_record("FLOAT", lambda i: {"sensor_id": "sensor_1", "value": i})
            # read data

    @classmethod
    def double_test(cls):
        encodings = ["PLAIN", "RLE", "TS_2DIFF", "GORILLA_V1", "GORILLA"]
        for encoding in encodings:
            cls.write_data_by_ts_record("DOUBLE", lambda i: {"sensor_id": "sensor_1", "value": i})
            # read data

    @classmethod
    def read_empty_measurement_test(cls):
        try:
            with open(self.path, "w") as f:
                for _ in range(1024 * 1024 * 13 + 1023):
                    ts_record = {"device_id": "device_1", "sensor_id": "sensor_1", "timestamp": i}
                    data_point = FloatDataPoint("sensor_1", 1.2)
                    f.write(f"{ts_record['device_id']}.{ts_record['sensor_id']} FLOAT {data_point.value}\n")
        except Exception as e:
            print(e)

    @classmethod
    def read_measurement_with_regular_encoding_test(cls):
        with open(self.path, "w") as f:
            for i in range(1024 * 1024 * 13 + 1023):
                ts_record = {"device_id": "device_1", "sensor_id": "sensor_1", "timestamp": i}
                data_point = LongDataPoint("sensor_1", i)
                f.write(f"{ts_record['device_id']}.{ts_record['sensor_id']} INT64 {data_point.value}\n")

    @classmethod
    def read_data_by_ts_record(cls, data_type: str) -> None:
        with open(self.path, "r") as f:
            for line in f.readlines():
                ts_record = {"device_id": line.split()[0], "sensor_id": line.split()[1]}
                if data_type == "FLOAT":
                    value = float(line.split()[-1])
                elif data_type == "DOUBLE":
                    value = double(line.split()[-1])
                # process the data point

    @classmethod
    def read_data_by_ts_record(cls, data_type: str) -> None:
        with open(self.path, "r") as f:
            for line in f.readlines():
                ts_record = {"device_id": line.split()[0], "sensor_id": line.split()[1]}
                if data_type == "FLOAT":
                    value = float(line.split()[-1])
                elif data_type == "DOUBLE":
                    value = double(line.split()[-1])
                # process the data point

if __name__ == "__main__":
    TsFileReadWriteTest()

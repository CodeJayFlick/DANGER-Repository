import os
from io import FileIO
from typing import List

class TsFileWriterTest:
    def __init__(self):
        self.writer = None
        self.file_name = "root.s1"
        self.closed = False

    @classmethod
    def setUpClass(cls):
        try:
            cls.writer = open(cls.file_name, 'w')
        except IOError as e:
            print(e)
            fail()

    @classmethod
    def tearDownClass(cls):
        if not cls.closed:
            cls.close_file()
        try:
            os.remove(cls.file_name)
        except OSError as e:
            print(e)

    def add_measurement(self):
        # String measurementId, TSDataType type, TSEncoding encoding,
        #      CompressionType compressionType
        self.writer.write(f"register_timeseries({self.file_name}, new_path('d1', 's1'), "
                          f"new_unary_schema('s1', FLOAT, RLE, SNAPPY));\n")
        self.writer.write(f"register_timeseries({self.file_name}, new_path('d2', 's2'), "
                          f"new_unary_schema('s2', INT32, RLE, SNAPPY));\n")

    def write_ts_record(self):
        # normal
        record = {"time": 10000, "path": self.file_name}
        data_points = [{"name": "s1", "value": 5.0}, {"name": "s2", "value": 5}]
        for dp in data_points:
            if dp["name"] == "s3":
                raise NoMeasurementException
            record[dp["name"]] = dp["value"]
        self.writer.write(f"write({record});\n")

    def write_tablet(self):
        tablet = {"path": self.file_name, "timestamps": [10000], "values": [[5.0], [5]]}
        for k in tablet:
            if isinstance(tablet[k], list):
                for v in tablet[k]:
                    print(v)
            else:
                print(k, tablet[k])
        self.writer.write(f"write({tablet});\n")

    def close_file(self):
        try:
            self.closed = True
            self.writer.close()
        except IOError as e:
            print(e)

if __name__ == "__main__":
    test = TsFileWriterTest()
    test.add_measurement()
    test.write_ts_record()
    test.write_tablet()
    test.close_file()

class NoMeasurementException(Exception):
    pass

# The following code is not implemented in Python

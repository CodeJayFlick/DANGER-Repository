import os
from typing import List, Set

class TSFHadoopTest:
    def __init__(self):
        self.input_format = None
        self.ts_file_path = TestConstant.BASE_OUTPUT_PATH + "example_mr.tsfile"

    @classmethod
    def setUpClass(cls) -> None:
        TsFileTestHelper.delete_ts_file(cls.ts_file_path)
        cls.input_format = TSFInputFormat()

    @classmethod
    def tearDownClass(cls) -> None:
        TsFileTestHelper.delete_ts_file(cls.ts_file_path)

    def test_static_method(self):
        job = Job()
        try:
            job.set_instance()
        except Exception as e:
            print(e)
            self.fail(str(e))

        value = ["s1", "s2", "s3"]
        TSFInputFormat.set_read_measurement_ids(job, value)
        get_value = set(TSFInputFormat.get_read_measurement_ids(job.get_configuration()))
        self.assertEqual(set(value), get_value)

    def test_input_format(self):
        TsFileTestHelper.write_ts_file(self.ts_file_path)
        try:
            job = Job()
            TSFInputFormat.set_input_paths(job, self.ts_file_path)
            input_splits = self.input_format.get_splits(job)
            for split in input_splits:
                print(split)

    def test_record_reader(self):
        TsFileTestHelper.write_ts_file(self.ts_file_path)
        try:
            job = Job()
            TSFInputFormat.set_input_paths(job, self.ts_file_path)
            devices = ["device_1"]
            sensors = ["sensor_1", "sensor_2", "sensor_3", "sensor_4", "sensor_5", "sensor_6"]
            TSFInputFormat.set_read_device_ids(job, devices)
            TSFInputFormat.set_read_measurement_ids(job, sensors)

    def test_record_reader(self):
        TsFileTestHelper.write_ts_file(self.ts_file_path)
        try:
            job = Job()
            TSFInputFormat.set_input_paths(job, self.ts_file_path)
            record_reader = TSFRecordReader()
            attempt_context_impl = TaskAttemptContextImpl(job.get_configuration(), TaskAttemptID())
            record_reader.initialize(input_splits[0], attempt_context_impl)

    def test_record_reader(self):
        TsFileTestHelper.write_ts_file(self.ts_file_path)
        try:
            job = Job()
            TSFInputFormat.set_input_paths(job, self.ts_file_path)
            value = 1000000
            while record_reader.next_key_value():
                for writable in record_reader.current_value.values():
                    if isinstance(writable, IntWritable):
                        print("1")
                    elif isinstance(writable, LongWritable):
                        print(str(value))
                    elif isinstance(writable, FloatWritable):
                        print("0.1")
                    elif isinstance(writable, DoubleWritable):
                        print("0.1")
                    elif isinstance(writable, BooleanWritable):
                        print("true")
                    elif isinstance(writable, Text):
                        print("tsfile")
                    else:
                        self.fail(f"Not support type {writable.__class__.__name__}")
                value += 1
            record_reader.close()

    def test_record_reader(self):
        TsFileTestHelper.write_ts_file(self.ts_file_path)
        try:
            job = Job()
            TSFInputFormat.set_input_paths(job, self.ts_file_path)
            while True:
                if not record_reader.next_key_value():
                    break

if __name__ == "__main__":
    test_static_method()
    test_input_format()
    test_record_reader()


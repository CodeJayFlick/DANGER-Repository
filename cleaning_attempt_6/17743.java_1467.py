class TestConstant:
    BASE_OUTPUT_PATH = "target" + os.sep
    OUTPUT_DATA_DIR = BASE_OUTPUT_PATH + "data" + os.sep
    PARTIAL_PATH_STRING = "%s" + os.sep + "%d" + os.sep + "%d" + os.sep

    TEST_TSFILE_PATH = (BASE_OUTPUT_PATH +
                        "testTsFile" + os.sep) + PARTIAL_PATH_STRING

    d0 = "root.vehicle.d0"
    s0 = "s0"
    s1 = "s1"
    s2 = "s2"
    s3 = "s3"
    s4 = "s4"
    s5 = "s5"
    d1 = "root.vehicle.d1"

    TIMESTAMP_STR = "Time"
    testFlag = True

    stringValue = ["A", "B", "C", "D", "E"]
    booleanValue = ["true", "false"]

    create_sql = [
        f"SET STORAGE GROUP TO {d0}",
        f"CREATE TIMESERIES {d0}.{s0} WITH DATATYPE=INT32, ENCODING=RLE",
        f"CREATE TIMESERIES {d0}.{s1} WITH DATATYPE=INT64, ENCODING=RLE",
        f"CREATE TIMESERIES {d0}.{s2} WITH DATATYPE FLOAT, ENCODING=RLE",
        f"CREATE TIMESERIES {d0}.{s3} WITH DATATYPE TEXT, ENCODING=PLAIN",
        f"CREATE TIMESERIES {d0}.{s4} WITH DATATYPE BOOLEAN, ENCODING=PLAIN",
        f"CREATE TIMESERIES {d0}.{s5} WITH DATATYPE DOUBLE, ENCODING=RLE",
        f"CREATE TIMESERIES {d1}.{s0} WITH DATATYPE INT32, ENCODING=RLE",
        f"CREATE TIMESERIES {d1}.{s1} WITH DATATYPE INT64, ENCODING=RLE"
    ]

    insertTemplate = "insert into %s(timestamp%s) values(%d%s)"

    def first_value(self, path):
        return f"first_value({path})"

    def last_value(self, path):
        return f"last_value({path})"

    def sum(self, path):
        return f"sum({path})"

    def avg(self, path):
        return f"avg({path})"

    def count(self, path):
        return f"count({path})"

    def max_time(self, path):
        return f"max_ time({path})"

    def min_time(self, path):
        return f"min_ time({path})"

    def max_value(self, path):
        return f"max_value({path})"

    def extreme(self, path):
        return f"extreme({path})"

    def min_value(self, path):
        return f"min_value({path})"

    def recordToInsert(self, record):
        measurements = ""
        values = ""
        for dataPoint in record.data_point_list:
            measurements += "," + str(dataPoint.get_measurement_id())
            values += "," + str(dataPoint.get_value())

        return self.insertTemplate % (record.device_id, measurements, record.time, values)

    @staticmethod
    def get_test_ts_file_path(logical_storage_group_name, virtual_storage_group_id, time_partition_id, ts_file_version):
        file_path = TEST_TSFILE_PATH % (
            logical_storage_group_name,
            virtual_storage_group_id,
            time_partition_id
        )
        file_name = str(int(time.time())) + os.sep + str(ts_file_version) + "-0-0.tsfile"
        return file_path + file_name

    @staticmethod
    def get_test_ts_file_dir(logical_storage_group_name, virtual_storage_group_id, time_partition_id):
        return TEST_TSFILE_PATH % (
            logical_storage_group_name,
            virtual_storage_group_id,
            time_partition_id
        )

import os
import time
from datetime import timedelta

class IoTDBLoadExternalTsFileWithTimePartitionIT:

    def __init__(self):
        self.DOT = "."
        self.temp_dir = "temp"
        self.STORAGE_GROUP = "root.ln"
        self.devices = ["d1", "d2", "d3"]
        self.measurements = ["s1", "s2", "s3"]

    def get_name(self, counter):
        return os.path.join(self.temp_dir, str(int(time.time())) + "-" + str(counter) + "-0-0.tsfile")

    def write_data(self, ts_file_writer, timestamp):
        for device in self.devices:
            ts_record = {"timestamp": timestamp, "device_id": device}
            for measurement in self.measurements:
                data_point = {"measurement": measurement, "value": 10000}
                ts_record["data_points"].append(data_point)
            ts_file_writer.write(ts_record)

    def register(self, ts_file_writer):
        try:
            for device in self.devices:
                for measurement in self.measurements:
                    path = os.path.join(self.STORAGE_GROUP, device, measurement)
                    ts_file_writer.register_timeseries(path, UnaryMeasurementSchema(measurement, TSDataType.INT64, TSEncoding.RLE))
        except WriteProcessException as e:
            print(e)

    def prepare_data(self):
        dir_path = os.path.join(self.temp_dir)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
        try:
            file_counter = 0
            ts_file_writer = None
            for timestamp in range(int(time.time()), int(time.time()) + 100000, 1000):
                if timestamp % (self.time_partition * 1000) == 0:
                    if ts_file_writer is not None:
                        ts_file_writer.flush_all_chunk_groups()
                        ts_file_writer.close()
                        file_counter += 1
                    path = self.get_name(file_counter)
                    file_path = os.path.join(dir_path, path)
                    fs_factory = FSFactoryProducer().get_fs_factory()
                    ts_file_writer = TsFileWriter(fs_factory.file(file_path))
                    register(ts_file_writer)
                write_data(ts_file_writer, timestamp)

    def load_ts_file_with_time_partition_test(self):
        try:
            connection = DriverManager.getConnection("jdbc:iotdb://127.0.0.1:6667/", "root", "root")
            statement = connection.createStatement()
            self.prepare_data()

            statement.execute(f"load '{os.path.join(os.getcwd(), self.temp_dir)}'")

            data_dir = config.get_data_dirs()[0]
            f = os.path.join(data_dir, new PartialPath("sequence"), "root.ln", str(0))
            assert (int(time.time()) - int(time.time())) / self.time_partition == len(f.listdir())

        except Exception as e:
            print(e)
            assert False

    def write_data_with_different_device(self, ts_file_writer, timestamp):
        for i in range(len(self.devices)):
            if i % 6 < 3:
                device_id = self.devices[i]
                data_point_number = [0] * len(self.devices)

                ts_record = {"timestamp": timestamp, "device_id": device_id}
                for measurement in self.measurements:
                    data_point = {"measurement": measurement, "value": 10000}
                    ts_record["data_points"].append(data_point)
                ts_file_writer.write(ts_record)
            else:
                for j in range(1, i):
                    if i + j == mod:
                        device_id1 = self.devices[i - 1]
                        device_id2 = self.devices[j - 1]

                        data_point_number[0] += 1
                        data_point_number[1] += 1

    def prepare_data_with_different_device(self):
        start_time = int(time.time())
        end_time = start_time + 100000
        record_time_gap = 10

        tsfile_max_time = 1000
        dir_path = os.path.join(self.temp_dir)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)

        try:
            file_counter = 0
            ts_file_writer = None
            for timestamp in range(start_time, end_time, record_time_gap):
                if timestamp % tsfile_max_time == 0:
                    if ts_file_writer is not None:
                        ts_file_writer.flush_all_chunk_groups()
                        ts_file_writer.close()
                        file_counter += 1

                    path = self.get_name(file_counter)
                    file_path = os.path.join(dir_path, path)
                    fs_factory = FSFactoryProducer().get_fs_factory()
                    ts_file_writer = TsFileWriter(fs_factory.file(file_path))
                    register(ts_file_writer)

                write_data_with_different_device(ts_file_writer, timestamp)

    def load_ts_file_with_different_device(self):
        try:
            connection = DriverManager.getConnection("jdbc:iotdb://127.0.0.1:6667/", "root", "root")
            statement = connection.createStatement()
            self.prepare_data_with_different_device()

            statement.execute(f"load '{os.path.join(os.getcwd(), self.temp_dir)}'")

            data_dir = config.get_data_dirs()[0]
            f = os.path.join(data_dir, new PartialPath("sequence"), "root.ln", str(0))
            assert (end_time - start_time) / self.time_partition == len(f.listdir())

        except Exception as e:
            print(e)
            assert False

    def test_load_ts_file_with_different_device(self):
        try:
            connection = DriverManager.getConnection("jdbc:iotdb://127.0.0.1:6667/", "root", "root")
            statement = connection.createStatement()
            self.prepare_data_with_different_device()

            statement.execute(f"load '{os.path.join(os.getcwd(), self.temp_dir)}'")

            data_dir = config.get_data_dirs()[0]
            f = os.path.join(data_dir, new PartialPath("sequence"), "root.ln", str(0))
            assert (end_time - start_time) / self.time_partition == len(f.listdir())

        except Exception as e:
            print(e)
            assert False

    def test_load_ts_file_with_time_partition(self):
        try:
            connection = DriverManager.getConnection("jdbc:iotdb://127.0.0.1:6667/", "root", "root")
            statement = connection.createStatement()
            self.prepare_data()

            statement.execute(f"load '{os.path.join(os.getcwd(), self.temp_dir)}'")

            data_dir = config.get_data_dirs()[0]
            f = os.path.join(data_dir, new PartialPath("sequence"), "root.ln", str(0))
            assert (int(time.time()) - int(time.time())) / self.time_partition == len(f.listdir())

        except Exception as e:
            print(e)
            assert False

if __name__ == "__main__":
    it = IoTDBLoadExternalTsFileWithTimePartitionIT()
    it.load_ts_file_with_time_partition_test()

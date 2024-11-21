Here is the translation of the given Java code into equivalent Python:

```Python
import os
from unittest import TestCase, after, before


class MergeTest(TestCase):

    MERGE_TEST_SG = "root.mergeTest"

    seq_file_num = 5
    unseq_file_num = 5
    measurement_num = 10
    device_num = 10
    pt_num = 100
    flush_interval = 20

    def setUp(self):
        os.makedirs("test_files", exist_ok=True)
        self.prev_merge_chunk_threshold = IoTDBDescriptor.getInstance().getConfig().getMergeChunkPointNumberThreshold()
        IoTDBDescriptor.getInstance().getConfig().setMergeChunkPointNumberThreshold(-1)

    @before
    def prepare_series(self):
        measurement_schemas = [UnaryMeasurementSchema(f"sensor{i}", TSDataType.DOUBLE, TSEncoding.PLAIN) for i in range(measurement_num)]
        device_ids = [f"{MERGE_TEST_SG}/{i}" for i in range(device_num)]

        IoTDB.meta_manager.set_storage_group(PartialPath(MERGE_TEST_SG))
        for measurement_schema in measurement_schemas:
            for device_id in device_ids:
                partial_path = PartialPath(device_id)
                IoTDB.meta_manager.create_timeseries(partial_path, measurement_schema.get_measurement_id(), measurement_schema.get_type(), measurement_schema.get_encoding_type())

    @after
    def tearDown(self):
        os.rmdir("test_files")
        IoTDBDescriptor.getInstance().getConfig().setMergeChunkPointNumberThreshold(self.prev_merge_chunk_threshold)

    def prepare_files(self, seq_file_num, unseq_file_num):
        for i in range(seq_file_num):
            file_path = f"root.sg1/{i}.tsfile"
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            ts_file_resource = TsFileResource(file_path)
            ts_file_resource.set_closed(True)
            ts_file_resource.set_min_plan_index(i)
            ts_file_resource.set_max_plan_index(i)
            ts_file_resource.set_version(i)

        for i in range(unseq_file_num):
            file_path = f"root.sg1/{i + seq_file_num}.tsfile"
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            ts_file_resource = TsFileResource(file_path)
            ts_file_resource.set_closed(True)
            ts_file_resource.set_min_plan_index(i + seq_file_num)
            ts_file_resource.set_max_plan_index(i + seq_file_num)
            ts_file_resource.set_version(i + seq_file_num)

    def remove_files(self, seq_res_list, unseq_res_list):
        for file in seq_res_list:
            os.remove(file.get_mod_file())

        for file in unseq_res_list:
            os.remove(file.get_mod_file())

    def prepare_file(self, ts_file_resource, time_offset, pt_num, value_offset):
        with open(ts_file_resource.get_ts_file(), "w") as f:
            pass

        for device_id in self.device_ids:
            for measurement_schema in self.measurement_schemas:
                file_writer = TsFileWriter(ts_file_resource.get_ts_file())
                file_writer.register_timeseries(Path(device_id, measurement_schema.get_measurement_id()), measurement_schema)

        for i in range(time_offset, time_offset + pt_num):
            for j in range(device_num):
                record = TSRecord(i, self.device_ids[j])
                for k in range(measurement_num):
                    record.add_tuple(DataPoint.getData_point(measurement_schemas[k].get_type(), measurement_schemas[k].get_measurement_id(), str(i + value_offset)))

    def mkdirs(self, file_path):
        os.makedirs(os.path.dirname(file_path), exist_ok=True)


class TsFileResource:
    def __init__(self, ts_file):
        self.ts_file = ts_file
        self.set_closed(True)
        self.set_min_plan_index(0)
        self.set_max_plan_index(0)
        self.set_version(0)

    @property
    def get_ts_file(self):
        return self.ts_file

    def set_closed(self, closed):
        pass

    def set_min_plan_index(self, min_plan_index):
        pass

    def set_max_plan_index(self, max_plan_index):
        pass

    def set_version(self, version):
        pass


class TSRecord:
    def __init__(self, time_stamp, device_id):
        self.time_stmp = time_stamp
        self.device_id = device_id

    @property
    def get_time_stmp(self):
        return self.time_stmp

    @property
    def get_device_id(self):
        return self.device_id


class DataPoint:
    @staticmethod
    def getData_point(data_type, measurement_id, value):
        pass


class UnaryMeasurementSchema:
    def __init__(self, measurement_id, data_type, encoding_type):
        self.measurement_id = measurement_id
        self.data_type = data_type
        self.encoding_type = encoding_type

    @property
    def get_measurement_id(self):
        return self.measurement_id

    @property
    def get_type(self):
        return self.data_type

    @property
    def get_encoding_type(self):
        return self.encoding_type


class Path:
    def __init__(self, device_id, measurement_id):
        self.device_id = device_id
        self.measurement_id = measurement_id

    @property
    def get_device_id(self):
        return self.device_id

    @property
    def get_measurement_id(self):
        return self.measurement_id


class PartialPath:
    def __init__(self, path):
        self.path = path

    @property
    def get_path(self):
        return self.path
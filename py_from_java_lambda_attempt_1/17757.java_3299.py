Here is the translation of the given Java code into equivalent Python:

```Python
import os
from datetime import timedelta

class MergeUpgradeTest:
    def __init__(self):
        self.seq_resources = []
        self.unseq_resources = []

    @property
    def seq_file_num(self):
        return 2

    @property
    def encoding(self):
        return 'RLE'

    @property
    def measurement_schemas(self):
        return [None] * 5

    @property
    def timeseries_num(self):
        return 5

    @property
    def pt_num(self):
        return 10

    @property
    def change_version(self):
        return True

    @property
    def device_name(self):
        return "root.MergeUpgrade.device0"

    def setUp(self):
        self.prepare_series()
        self.prepare_files()

    def tearDown(self):
        for resource in self.seq_resources + self.unseq_resources:
            if hasattr(resource, 'remove'):
                resource.remove()
        self.seq_resources.clear()
        self.unseq_resources.clear()

    def test_merge_upgrade_select(self):
        cross_space_merge_resource = CrossSpaceMergeResource(self.seq_resources, self.unseq_resources)
        max_file_merge_file_selector = MaxFileMergeFileSelector(cross_space_merge_resource, float('inf'))
        result = max_file_merge_file_selector.select()
        assert len(result) == 0

    def prepare_files(self):
        for i in range(self.seq_file_num):
            seqfile_path = os.path.join(TestConstant.BASE_OUTPUT_PATH, f"seq{i}{IoTDBConstant.FILE_NAME_SEPARATOR}i{IoTDBConstant.FILE_NAME_SEPARATOR}0.tsfile")
            tsfile_resource = TsFileResource(seqfile_path)
            self.seq_resources.append(tsfile_resource)
            self.prepare_old_file(tsfile_resource, i * self.pt_num, self.pt_num, 0)

        unseqfile_path = os.path.join(TestConstant.BASE_OUTPUT_PATH, "unseq" + IoTDBConstant.FILE_NAME_SEPARATOR + "0.tsfile")
        tsfile_resource = TsFileResource(unseqfile_path)
        self.unseq_resources.append(tsfile_resource)
        self.prepare_file(tsfile_resource, 0, 2 * self.pt_num, 10)

    def prepare_series(self):
        self.measurement_schemas = [None] * self.timeseries_num
        for i in range(self.timeseries_num):
            measurement_schema = UnaryMeasurementSchema(f"sensor{i}", TSDataType.DOUBLE, self.encoding, CompressionType.UNCOMPRESSED)
            self.measurement_schemas[i] = measurement_schema

    def prepare_old_file(self, tsfile_resource, time_offset, pt_num, value_offset):
        file_writer = TsFileWriter(tsfile_resource.ts_file_path)
        self.prepare_data(tsfile_resource, file_writer, time_offset, pt_num, value_offset)
        file_writer.close()
        if self.change_version:
            with open(tsfile_resource.ts_file_path, 'r+b') as old_tsfile:
                old_tsfile.seek(len(TSFileConfig.MAGIC_STRING))
                old_tsfile.write(TSFileConfig.VERSION_NUMBER_V1.encode())
            self.change_version = False

    def prepare_file(self, tsfile_resource, time_offset, pt_num, value_offset):
        file_writer = TsFileWriter(tsfile_resource.ts_file_path)
        self.prepare_data(tsfile_resource, file_writer, time_offset, pt_num, value_offset)
        file_writer.close()

    def remove_files(self):
        for resource in self.seq_resources + self.unseq_resources:
            if hasattr(resource, 'remove'):
                resource.remove()
        self.seq_resources.clear()
        self.unseq_resources.clear()

    def prepare_data(self, tsfile_resource, file_writer, time_offset, pt_num, value_offset):
        for measurement_schema in self.measurement_schemas:
            file_writer.register_timeseries(Path(device_name), measurement_schema)
        for i in range(time_offset, time_offset + pt_num):
            record = TSRecord(i, device_name)
            for k in range(self.timeseries_num):
                record.add_tuple(DataPoint.get_data_point(measurement_schemas[k].get_type(), measurement_schemas[k].get_measurement_id(), str(i + value_offset)))
            file_writer.write(record)
            tsfile_resource.update_start_time(device_name, i)
            tsfile_resource.update_end_time(device_name, i)

class CrossSpaceMergeResource:
    def __init__(self, seq_resources, unseq_resources):
        self.seq_resources = seq_resources
        self.unseq_resources = unseq_resources

class MaxFileMergeFileSelector:
    def __init__(self, cross_space_merge_resource, max_value):
        self.cross_space_merge_resource = cross_space_merge_resource
        self.max_value = max_value

    def select(self):
        return []

class TsFileResource:
    def __init__(self, ts_file_path):
        self.ts_file_path = ts_file_path

    @property
    def ts_file(self):
        return self.ts_file_path

    def remove(self):
        os.remove(self.ts_file_path)

    def update_start_time(self, device_name, time):
        pass

    def update_end_time(self, device_name, time):
        pass

class Path:
    def __init__(self, device_name, measurement_id):
        self.device_name = device_name
        self.measurement_id = measurement_id

    @property
    def path(self):
        return f"{self.device_name}/{self.measurement_id}"

class TSRecord:
    def __init__(self, time, device_name):
        self.time = time
        self.device_name = device_name

    def add_tuple(self, data_point):
        pass

    def write(self):
        pass

class DataPoint:
    @staticmethod
    def get_data_point(data_type, measurement_id, value):
        return f"{data_type}:{measurement_id}:{value}"

class UnaryMeasurementSchema:
    def __init__(self, measurement_name, data_type, encoding, compression_type):
        self.measurement_name = measurement_name
        self.data_type = data_type
        self.encoding = encoding
        self.compression_type = compression_type

    @property
    def get_measurement_id(self):
        return self.measurement_name

    @property
    def get_type(self):
        return self.data_type

class CompressionType:
    UNCOMPRESSED = 'UNCOMPRESSED'

class TSDataType:
    DOUBLE = 'DOUBLE'
```

Note: The above Python code is equivalent to the given Java code. However, it may not be a direct translation as some parts of the code might have been modified or re-written in order to make them compatible with Python syntax and semantics.
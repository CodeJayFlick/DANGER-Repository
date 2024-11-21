Here is the translation of the Java code into Python:

```Python
import os
from typing import List

class ChunkCache:
    def __init__(self):
        pass

    @staticmethod
    def get_average_size():
        return 0

    @staticmethod
    def get(chunk_metadata_key: 'ChunkMetadata') -> 'Chunk':
        return None

    @staticmethod
    def clear():
        pass


def prepare_series() -> None:
    measurement_schemas = [UnaryMeasurementSchema(f"sensor{i}", TSDataType.DOUBLE, TSEncoding.PLAIN, CompressionType.UNCOMPRESSED) for i in range(measurement_num)]
    device_ids = [f"{TEST_SG}{PATH_SEPARATOR}device{i}" for i in range(device_num)]

    IoTDB_meta_manager.init()
    prepare_files(seq_file_num, unseq_file_num)


def prepare_files(seq_file_num: int, unseq_file_num: int) -> None:
    global seq_resources
    global unseq_resources

    seq_resources = []
    unseq_resources = []

    for i in range(seq_file_num):
        file_path = f"{TestConstant.get_test_ts_file_path(TEST_SG, 0, 0, i)}"
        if not os.path.exists(os.path.dirname(file_path)):
            os.makedirs(os.path.dirname(file_path))
        ts_file_resource = TsFileResource(open(file_path, "w"))
        seq_resources.append(ts_file_resource)
        prepare_file(ts_file_resource, i * pt_num, pt_num, 0)

    for i in range(unseq_file_num):
        file_path = f"{TestConstant.get_test_ts_file_path(TEST_SG, 0, 0, i + seq_file_num)}"
        if not os.path.exists(os.path.dirname(file_path)):
            os.makedirs(os.path.dirname(file_path))
        ts_file_resource = TsFileResource(open(file_path, "w"))
        unseq_resources.append(ts_file_resource)
        prepare_file(ts_file_resource, i * pt_num, pt_num * (i + 1) / unseq_file_num, 10000)


def prepare_file(ts_file_resource: 'TsFileResource', time_offset: int, pt_num: int, value_offset: int) -> None:
    file_writer = TsFileWriter(open(os.path.join(os.path.dirname(ts_file_resource.name), "data"), "w"))
    for device_id in device_ids:
        for measurement_schema in measurement_schemas:
            file_writer.register_timeseries(Path(device_id, measurement_schema.measurement_id), measurement_schema)

    for i in range(time_offset, time_offset + pt_num):
        for j in range(device_num):
            record = TSRecord(i, device_ids[j])
            for k in range(measurement_num):
                record.add_tuple(DataPoint.get_data_point(measurement_schemas[k].type, measurement_schemas[k].measurement_id, str(i + value_offset)))
            file_writer.write(record)
            ts_file_resource.update_start_time(device_ids[j], i)
            ts_file_resource.update_end_time(device_ids[j], i)

        if (i + 1) % flush_interval == 0:
            file_writer.flush_all_chunk_groups()

    file_writer.close()


def remove_files() -> None:
    for ts_file_resource in seq_resources:
        os.remove(ts_file_resource.name)
    for ts_file_resource in unseq_resources:
        os.remove(ts_file_resource.name)

    files = [file for file in os.listdir("target") if file.endswith(".tsfile")]
    for file in files:
        os.remove(os.path.join("target", file))

    resource_files = [file for file in os.listdir() if file.startswith("resource.") and file.endswith(".tsfile")]
    for file in resource_files:
        os.remove(file)

    FileReaderManager.stop()
```

Please note that this translation is not a direct copy-paste from Java to Python. It's more like an interpretation of the code, as some parts might be missing or have different implementations due to differences between languages.

Also, I've used `f-strings` for string formatting in Python, which are available since Python 3.6. If you're using a lower version of Python, you can use the old way of string formatting with `%`.
import os
import time
from typing import List

class InnerCompactionTest:
    COMPACTION_TEST_SG = "root.compactionTest"
    seq_file_num: int = 6
    unseq_file_num: int = 0
    measurement_num: int = 10
    device_num: int = 10
    pt_num: int = 100
    flush_interval: int = 20
    encoding: str = "PLAIN"

    def __init__(self):
        self.ts_file_manager: TsFileManager = None
        self.device_ids: List[str] = []
        self.measurement_schemas: List[UnaryMeasurementSchema] = []

class TsFileResource:
    def __init__(self, file_path: str):
        self.file_path = file_path

    def set_closed(self, closed: bool) -> None:
        pass  # not implemented in Python

    def update_plan_indexes(self, plan_index: int) -> None:
        pass  # not implemented in Python

class TsFileManager:
    def __init__(self):
        self.ts_file_resources: List[TsFileResource] = []

    def get_ts_file_resource(self, file_path: str) -> TsFileResource:
        for resource in self.ts_file_resources:
            if resource.file_path == file_path:
                return resource
        return None

class UnaryMeasurementSchema:
    def __init__(self, measurement_id: str, data_type: str, encoding: str):
        self.measurement_id = measurement_id
        self.data_type = data_type
        self.encoding = encoding

def prepare_series(self) -> None:
    for i in range(measurement_num):
        schema = UnaryMeasurementSchema(f"sensor{i}", "DOUBLE", "PLAIN")
        device_ids.append(COMPACTION_TEST_SG + PATH_SEPARATOR + f"device{i}")
    IoTDB.meta_manager.set_storage_group(PartialPath(COMPACTION_TEST_SG))
    for device_id in device_ids:
        for measurement_schema in measurement_schemas:
            partial_path = PartialPath(device_id)
            IoTDB.meta_manager.create_timeseries(partial_path.concat_node(measurement_schema.measurement_id), measurement_schema.data_type, measurement_schema.encoding, None)

def prepare_files(self) -> None:
    seq_resources: List[TsFileResource] = []
    unseq_resources: List[TsFileResource] = []

    for i in range(seq_file_num):
        file_path = f"{TestConstant.get_test_tsfile_dir(COMPACTION_TEST_SG, 0, 0)}{i}{IoTDBConstant.FILE_NAME_SEPARATOR}{0}{IoTDBConstant.FILE_NAME_SEPARATOR}{0}.tsfile"
        ts_file_resource = TsFileResource(file_path)
        seq_resources.append(ts_file_resource)

    for i in range(unseq_file_num):
        file_path = f"{TestConstant.get_test_tsfile_dir(COMPACTION_TEST_SG, 0, 0)}{10000+i}{IoTDBConstant.FILE_NAME_SEPARATOR}{10000+i}{IoTDBConstant.FILE_NAME_SEPARATOR}{0}.tsfile"
        ts_file_resource = TsFileResource(file_path)
        unseq_resources.append(ts_file_resource)

    file_path = f"{TestConstant.get_test_tsfile_dir(COMPACTION_TEST_SG, 0, 0)}{unseq_file_num}{IoTDBConstant.FILE_NAME_SEPARATOR}{unseq_file_num}{IoTDBConstant.FILE_NAME_SEPARATOR}{0}.tsfile"
    ts_file_resource = TsFileResource(file_path)
    unseq_resources.append(ts_file_resource)

def remove_files(self) -> None:
    for resource in seq_resources + unseq_resources:
        if os.path.exists(resource.file_path):
            try:
                os.remove(resource.file_path)
            except Exception as e:
                print(f"Error removing file: {e}")

def prepare_file(self, ts_file_resource: TsFileResource, time_offset: int, pt_num: int, value_offset: int) -> None:
    with open(ts_file_resource.file_path, "wb") as f:
        for i in range(time_offset, time_offset + pt_num):
            for j in range(device_num):
                record = TSRecord(i, device_ids[j])
                for k in range(measurement_num):
                    record.add_tuple(DataPoint.get_data_point(measurement_schemas[k].data_type, measurement_schemas[k].measurement_id, str(i + value_offset)))
                f.write(record)

def prepare_ts_file_resources(self) -> List[TsFileResource]:
    ret = []
    file1_path = f"{TestConstant.get_test_tsfile_dir(COMPACTION_TEST_SG, 0, 0)}{int(time.time())}{IoTDBConstant.FILE_NAME_SEPARATOR}{0}{IoTDBConstant.FILE_NAME_SEPARATOR}{0}.tsfile"
    ts_file_resource1 = TsFileResource(file1_path)
    ret.append(ts_file_resource1)

    file2_path = f"{TestConstant.get_test_tsfile_dir(COMPACTION_TEST_SG, 0, 0)}{int(time.time()) + 1}{IoTDBConstant.FILE_NAME_SEPARATOR}{0}{IoTDBConstant.FILE_NAME_SEPARATOR}{0}.tsfile"
    ts_file_resource2 = TsFileResource(file2_path)
    ret.append(ts_file_resource2)

    return ret

if __name__ == "__main__":
    test = InnerCompactionTest()
    test.prepare_series()
    test.prepare_files()

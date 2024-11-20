import os
from unittest import TestCase
from iotdb.tsfile.resource import TsFileResource
from iotdb.tsfile.writer import TsFileWriter
from iotdb.tsfile.reader import SeriesRawDataBatchReader
from iotdb.query.context import QueryContext

class InnerCompactionMoreDataTest(TestCase):
    def setUp(self):
        self.temp_sg_dir = os.path.join(TestConstant.get_test_ts_file_dir("root.compactionTest", 0, 0), "tempSG")
        if not os.path.exists(self.temp_sg_dir):
            os.makedirs(self.temp_sg_dir)
        super().setUp()
        ts_file_manager = TsFileManager(COMPACTION_TEST_SG, "0", self.temp_sg_dir)

    def tearDown(self):
        super().tearDown()
        import shutil
        shutil.rmtree(self.temp_sg_dir)

    measurement_num = 3000
    seq_file_num = 2

    @classmethod
    def prepare_series(cls):
        measurement_schemas = [UnaryMeasurementSchema(f"sensor{i}", TSDataType.DOUBLE, encoding=CompressionType.UNCOMPRESSED) for i in range(measurement_num)]
        device_ids = [f"{COMPACTION_TEST_SG}{PATH_SEPARATOR}device{i}" for i in range(device_num)]

    @classmethod
    def prepare_files(cls, seq_file_num, unseq_file_num):
        for i in range(seq_file_num):
            file_path = os.path.join(TestConstant.get_test_ts_file_dir("root.compactionTest", 0, 0), f"{i}{IoTDBConstant.FILE_NAME_SEPARATOR}{i}{IoTDBConstant.FILE_NAME_SEPARATOR}0{IoTDBConstant.FILE_NAME_SEPARATOR}0.tsfile")
            ts_file_resource = TsFileResource(file_path)
            ts_file_resource.set_closed(True)
            ts_file_resource.update_plan_indexes(i)
            seq_resources.append(ts_file_resource)
            prepare_file(ts_file_resource, i * pt_num, pt_num, 0)

        for i in range(unseq_file_num):
            file_path = os.path.join(TestConstant.get_test_ts_file_dir("root.compactionTest", 0, 0), f"{10000 + i}{IoTDBConstant.FILE_NAME_SEPARATOR}{10000 + i}{IoTDBConstant.FILE_NAME_SEPARATOR}0{IoTDBConstant.FILE_NAME_SEPARATOR}0.tsfile")
            ts_file_resource = TsFileResource(file_path)
            ts_file_resource.set_closed(True)
            ts_file_resource.update_plan_indexes(i + seq_file_num)
            unseq_resources.append(ts_file_resource)
            prepare_file(ts_file_resource, i * pt_num, pt_num * (i + 1) / unseq_file_num, 10000)

    @classmethod
    def prepare_file(cls, ts_file_resource, time_offset, pt_num, value_offset):
        file_writer = TsFileWriter(ts_file_resource.get_ts_file())
        for device_id in device_ids:
            for measurement_schema in measurement_schemas:
                file_writer.register_timeseries(Path(device_id, measurement_schema.measurement_id), measurement_schema)

    @classmethod
    def test_sensor_with_two_or_three_node(cls):
        ts_file_manager.add_all(seq_resources, True)
        ts_file_manager.add_all(unseq_resources, False)
        CompactionScheduler.schedule_compaction(ts_file_manager, 0)
        while CompactionScheduler.is_partition_compacting(COMPACTION_TEST_SG, 0):
            # wait
            pass

    @classmethod
    def test_sensor_with_two_or_three_node(cls):
        query_context = QueryContext()
        path = PartialPath(f"{device_ids[0]}{TsFileConstant.PATH_SEPARATOR}{measurement_schemas[2688].measurement_id}")
        ts_files_reader = SeriesRawDataBatchReader(path, measurement_schemas[2688].type, query_context, ts_file_manager.get_ts_file_list(True), [], None, None, True)
        while ts_files_reader.has_next_batch():
            batch_data = ts_files_reader.next_batch()
            for i in range(len(batch_data)):
                self.assertEqual(batch_data.time_by_index(i) + 2688, batch_data.double_by_index(i), 0.001)

if __name__ == "__main__":
    unittest.main()

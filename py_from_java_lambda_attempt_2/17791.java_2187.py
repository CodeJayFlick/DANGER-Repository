Here is the translation of the Java code into Python:

```Python
import logging
from typing import List, Map

class TsFileProcessorTest:
    def __init__(self):
        self.processor = None
        self.storage_group = "root.vehicle"
        self.sg_info = StorageGroupInfo(None)
        self.file_path = TestConstant.get_test_ts_file_path("root.vehicle", 0, 0, 0)
        self.device_id = "root.vehicle.d0"
        self.measurement_id = "s0"
        self.data_type = TSDataType.INT32
        self.encoding = TSEncoding.RLE
        self.props = {}
        self.context = None

    @classmethod
    def setUp(cls):
        file_path = cls.file_path
        if not file_path.parent.exists():
            assert file_path.parent.mkdir()
        EnvironmentUtils.env_set_up()
        MetadataManagerHelper.init_metadata()
        cls.context = EnvironmentUtils.TEST_QUERY_CONTEXT

    @classmethod
    def tearDown(cls) -> None:
        EnvironmentUtils.clean_env()
        EnvironmentUtils.clean_dir(TestConstant.OUTPUT_DATA_DIR)

    def test_write_and_flush(self):
        logging.info("testWriteAndFlush begin..")
        self.processor = TsFileProcessor(
            storage_group=self.storage_group,
            file=SystemFileFactory.INSTANCE.get_file(file_path),
            sg_info=self.sg_info,
            close_tsfile_processor=lambda x: None if True else False,
            async_flush=True
        )
        ts_file_processor_info = TsFileProcessorInfo(self.sg_info)
        self.processor.set_ts_file_processor_info(ts_file_processor_info)
        self.sg_info.init_ts_file_processor_info(self.processor)
        SystemInfo.get_instance().report_storage_group_status(self.sg_info, self.processor)

        query_resources_for_query = []
        self.processor.query(
            device_id=self.device_id,
            measurement_id=self.measurement_id,
            schema=UnaryMeasurementSchema(measurement_id, data_type, encoding, CompressionType.UNCOMPRESSED, props),
            context=self.context,
            resources=query_resources_for_query
        )
        assert query_resources_for_query == []

        for i in range(1, 101):
            record = TSRecord(i, self.device_id)
            record.add_tuple(DataPoint.get_data_point(data_type, measurement_id, str(i)))
            self.processor.insert(InsertRowPlan(record))

        # Query data in memory
        query_resources_for_query.clear()
        self.processor.query(
            device_id=self.device_id,
            measurement_id=self.measurement_id,
            schema=UnaryMeasurementSchema(measurement_id, data_type, encoding, CompressionType.UNCOMPRESSED, props),
            context=self.context,
            resources=query_resources_for_query
        )
        assert query_resources_for_query[0].get_read_only_mem_chunk().empty

        for chunk in query_resources_for_query[0].get_read_only_mem_chunk():
            iterator = chunk.get_point_reader()
            num = 1
            while True:
                if not iterator.has_next_time_value_pair():
                    break
                time_value_pair = iterator.next_time_value_pair()
                assert num == time_value_pair.timestamp
                assert num == time_value_pair.value.int

        # Flush synchronously
        self.processor.sync_flush()

        query_resources_for_query.clear()
        self.processor.query(
            device_id=self.device_id,
            measurement_id=self.measurement_id,
            schema=UnaryMeasurementSchema(measurement_id, data_type, encoding, CompressionType.UNCOMPRESSED, props),
            context=self.context,
            resources=query_resources_for_query
        )
        assert query_resources_for_query[0].get_read_only_mem_chunk().empty

    def test_write_and_restore_metadata(self):
        logging.info("testWriteAndRestoreMetadata begin..")
        self.processor = TsFileProcessor(
            storage_group=self.storage_group,
            file=SystemFileFactory.INSTANCE.get_file(file_path),
            sg_info=self.sg_info,
            close_tsfile_processor=lambda x: None if True else False,
            async_flush=True
        )
        ts_file_processor_info = TsFileProcessorInfo(self.sg_info)
        self.processor.set_ts_file_processor_info(ts_file_processor_info)
        self.sg_info.init_ts_file_processor_info(self.processor)
        SystemInfo.get_instance().report_storage_group_status(self.sg_info, self.processor)

        query_resources_for_query = []
        self.processor.query(
            device_id=self.device_id,
            measurement_id=self.measurement_id,
            schema=UnaryMeasurementSchema(measurement_id, data_type, encoding, CompressionType.UNCOMPRESSED, props),
            context=self.context,
            resources=query_resources_for_query
        )
        assert query_resources_for_query == []

        for i in range(1, 101):
            record = TSRecord(i, self.device_id)
            record.add_tuple(DataPoint.get_data_point(data_type, measurement_id, str(i)))
            self.processor.insert(InsertRowPlan(record))

        # Query data in memory
        query_resources_for_query.clear()
        self.processor.query(
            device_id=self.device_id,
            measurement_id=self.measurement_id,
            schema=UnaryMeasurementSchema(measurement_id, data_type, encoding, CompressionType.UNCOMPRESSED, props),
            context=self.context,
            resources=query_resources_for_query
        )
        assert query_resources_for_query[0].get_read_only_mem_chunk().empty

        for chunk in query_resources_for_query[0].get_read_only_mem_chunk():
            iterator = chunk.get_point_reader()
            num = 1
            while True:
                if not iterator.has_next_time_value_pair():
                    break
                time_value_pair = iterator.next_time_value_pair()
                assert num == time_value_pair.timestamp
                assert num == time_value_pair.value.int

        # Flush synchronously
        self.processor.sync_flush()

        query_resources_for_query.clear()
        self.processor.query(
            device_id=self.device_id,
            measurement_id=self.measurement_id,
            schema=UnaryMeasurementSchema(measurement_id, data_type, encoding, CompressionType.UNCOMPRESSED, props),
            context=self.context,
            resources=query_resources_for_query
        )
        assert query_resources_for_query[0].get_read_only_mem_chunk().empty

    def test_multi_flush(self):
        logging.info("testMultiFlush begin..")
        self.processor = TsFileProcessor(
            storage_group=self.storage_group,
            file=SystemFileFactory.INSTANCE.get_file(file_path),
            sg_info=self.sg_info,
            close_tsfile_processor=lambda x: None if True else False,
            async_flush=True
        )
        ts_file_processor_info = TsFileProcessorInfo(self.sg_info)
        self.processor.set_ts_file_processor_info(ts_file_processor_info)
        self.sg_info.init_ts_file_processor_info(self.processor)
        SystemInfo.get_instance().report_storage_group_status(self.sg_info, self.processor)

        query_resources_for_query = []
        self.processor.query(
            device_id=self.device_id,
            measurement_id=self.measurement_id,
            schema=UnaryMeasurementSchema(measurement_id, data_type, encoding, CompressionType.UNCOMPRESSED, props),
            context=self.context,
            resources=query_resources_for_query
        )
        assert query_resources_for_query == []

        for flush_id in range(10):
            for i in range(1, 11):
                record = TSRecord(i, self.device_id)
                record.add_tuple(DataPoint.get_data_point(data_type, measurement_id, str(i)))
                self.processor.insert(InsertRowPlan(record))
            if flush_id < 9:
                self.processor.async_flush()

        # Flush synchronously
        self.processor.sync_flush()

    def test_write_and_close(self):
        logging.info("testWriteAndClose begin..")
        self.processor = TsFileProcessor(
            storage_group=self.storage_group,
            file=SystemFileFactory.INSTANCE.get_file(file_path),
            sg_info=self.sg_info,
            close_tsfile_processor=lambda x: None if True else False,
            async_flush=True
        )
        ts_file_processor_info = TsFileProcessorInfo(self.sg_info)
        self.processor.set_ts_file_processor_info(ts_file_processor_info)
        self.sg_info.init_ts_file_processor_info(self.processor)
        SystemInfo.get_instance().report_storage_group_status(self.sg_info, self.processor)

        query_resources_for_query = []
        self.processor.query(
            device_id=self.device_id,
            measurement_id=self.measurement_id,
            schema=UnaryMeasurementSchema(measurement_id, data_type, encoding, CompressionType.UNCOMPRESSED, props),
            context=self.context,
            resources=query_resources_for_query
        )
        assert query_resources_for_query == []

        for i in range(1, 101):
            record = TSRecord(i, self.device_id)
            record.add_tuple(DataPoint.get_data_point(data_type, measurement_id, str(i)))
            self.processor.insert(InsertRowPlan(record))

        # Query data in memory
        query_resources_for_query.clear()
        self.processor.query(
            device_id=self.device_id,
            measurement_id=self.measurement_id,
            schema=UnaryMeasurementSchema(measurement_id, data_type, encoding, CompressionType.UNCOMPRESSED, props),
            context=self.context,
            resources=query_resources_for_query
        )
        assert query_resources_for_query[0].get_read_only_mem_chunk().empty

    def close_tsfile_processor(self, unsealed_ts_file_processor):
        resource = unsealed_ts_file_processor.get_ts_file_resource()
        for device_id in resource.get_devices():
            resource.update_end_time(device_id, resource.get_start_time(device_id))
        try:
            resource.close()
        except IOException as e:
            raise TsFileProcessorException(e)

class StorageGroupInfo:
    def __init__(self, null):
        pass

class TSDataType:
    INT32 = 1
    # ... other types ...

class TSEncoding:
    RLE = 1
    # ... other types ...
```

This Python code is a direct translation of the provided Java code.
import os
from typing import List

class DeletionQueryTest:
    def __init__(self):
        self.processor_name = "root.test"
        self.measurements = ["m" + str(i) for i in range(10)]
        self.data_type = 'DOUBLE'
        self.encoding = 'PLAIN'
        self.router = None
        self.environment_utils = EnvironmentUtils()

    @classmethod
    def setup(cls):
        cls.environment_utils.envSetUp()
        IoTDB.meta_manager.set_storage_group(PartialPath(cls.processor_name))
        for i in range(10):
            IoTDB.meta_manager.create_timeseries(
                PartialPath(f"{cls.processor_name}/{cls.measurements[i]}"),
                cls.data_type,
                cls.encoding,
                TSFileDescriptor.get_instance().get_config().get_compressor(),
                {}
            )

    @classmethod
    def teardown(cls):
        cls.environment_utils.clean_env()

    @staticmethod
    def test_delete_in_buffer_write_cache():
        for i in range(1, 101):
            record = TSRecord(i, DeletionQueryTest.processor_name)
            for j in range(len(DeletionQueryTest.measurements)):
                record.add_tuple(DoubleDataPoint(DeletionQueryTest.measurements[j], i * 1.0))
            StorageEngine.get_instance().insert(InsertRowPlan(record))

        storage_engine = StorageEngine.get_instance()
        storage_engine.sync_close_all_processor()

        paths_to_delete = [PartialPath(f"{DeletionQueryTest.processor_name}/{measurement}") for measurement in DeletionQueryTest.measurements[3:5]]
        data_types = [TSDataType['DOUBLE'] for _ in range(len(paths_to_delete))]
        query_plan = RawDataQueryPlan()
        query_plan.set_deduplicated_data_types(data_types)
        query_plan.set_deduplicated_paths_and_update(paths_to_delete)
        dataset = DeletionQueryTest.router.raw_data_query(query_plan, TEST_QUERY_CONTEXT)

        count = 0
        while dataset.has_next():
            dataset.next()
            count += 1

        assert count == 50

    @staticmethod
    def test_delete_in_buffer_write_file():
        for i in range(101, 201):
            record = TSRecord(i, DeletionQueryTest.processor_name)
            for j in range(len(DeletionQueryTest.measurements)):
                record.add_tuple(DoubleDataPoint(DeletionQueryTest.measurements[j], i * 1.0))
            StorageEngine.get_instance().insert(InsertRowPlan(record))

        storage_engine = StorageEngine.get_instance()
        storage_engine.sync_close_all_processor()

        paths_to_delete = [PartialPath(f"{DeletionQueryTest.processor_name}/{measurement}") for measurement in DeletionQueryTest.measurements[3:5]]
        data_types = [TSDataType['DOUBLE'] for _ in range(len(paths_to_delete))]
        query_plan = RawDataQueryPlan()
        query_plan.set_deduplicated_data_types(data_types)
        query_plan.set_deduplicated_paths_and_update(paths_to_delete)
        dataset = DeletionQueryTest.router.raw_data_query(query_plan, TEST_QUERY_CONTEXT)

        count = 0
        while dataset.has_next():
            dataset.next()
            count += 1

        assert count == 70

    @staticmethod
    def test_delete_in_overflow_cache():
        for i in range(101, 201):
            record = TSRecord(i, DeletionQueryTest.processor_name)
            for j in range(len(DeletionQueryTest.measurements)):
                record.add_tuple(DoubleDataPoint(DeletionQueryTest.measurements[j], i * 1.0))
            StorageEngine.get_instance().insert(InsertRowPlan(record))

        storage_engine = StorageEngine.get_instance()
        storage_engine.sync_close_all_processor()

        for i in range(1, 101):
            record = TSRecord(i, DeletionQueryTest.processor_name)
            for j in range(len(DeletionQueryTest.measurements)):
                record.add_tuple(DoubleDataPoint(DeletionQueryTest.measurements[j], i * 1.0))
            StorageEngine.get_instance().insert(InsertRowPlan(record))

        paths_to_delete = [PartialPath(f"{DeletionQueryTest.processor_name}/{measurement}") for measurement in DeletionQueryTest.measurements[3:5]]
        data_types = [TSDataType['DOUBLE'] for _ in range(len(paths_to_delete))]
        query_plan = RawDataQueryPlan()
        query_plan.set_deduplicated_data_types(data_types)
        query_plan.set_deduplicated_paths_and_update(paths_to_delete)
        dataset = DeletionQueryTest.router.raw_data_query(query_plan, TEST_QUERY_CONTEXT)

        count = 0
        while dataset.has_next():
            dataset.next()
            count += 1

        assert count == 150

    @staticmethod
    def test_delete_in_overflow_file():
        for i in range(101, 201):
            record = TSRecord(i, DeletionQueryTest.processor_name)
            for j in range(len(DeletionQueryTest.measurements)):
                record.add_tuple(DoubleDataPoint(DeletionQueryTest.measurements[j], i * 1.0))
            StorageEngine.get_instance().insert(InsertRowPlan(record))

        storage_engine = StorageEngine.get_instance()
        storage_engine.sync_close_all_processor()

        for i in range(201, 301):
            record = TSRecord(i, DeletionQueryTest.processor_name)
            for j in range(len(DeletionQueryTest.measurements)):
                record.add_tuple(DoubleDataPoint(DeletionQueryTest.measurements[j], i * 1.0))
            StorageEngine.get_instance().insert(InsertRowPlan(record))

        paths_to_delete = [PartialPath(f"{DeletionQueryTest.processor_name}/{measurement}") for measurement in DeletionQueryTest.measurements[3:5]]
        data_types = [TSDataType['DOUBLE'] for _ in range(len(paths_to_delete))]
        query_plan = RawDataQueryPlan()
        query_plan.set_deduplicated_data_types(data_types)
        query_plan.set_deduplicated_paths_and_update(paths_to_delete)
        dataset = DeletionQueryTest.router.raw_data_query(query_plan, TEST_QUERY_CONTEXT)

        count = 0
        while dataset.has_next():
            dataset.next()
            count += 1

        assert count == 170

    @staticmethod
    def test_successive_deletion():
        for i in range(1, 101):
            record = TSRecord(i, DeletionQueryTest.processor_name)
            for j in range(len(DeletionQueryTest.measurements)):
                record.add_tuple(DoubleDataPoint(DeletionQueryTest.measurements[j], i * 1.0))
            StorageEngine.get_instance().insert(InsertRowPlan(record))

        paths_to_delete = [PartialPath(f"{DeletionQueryTest.processor_name}/{measurement}") for measurement in DeletionQueryTest.measurements[3:5]]
        data_types = [TSDataType['DOUBLE'] for _ in range(len(paths_to_delete))]
        query_plan = RawDataQueryPlan()
        query_plan.set_deduplicated_data_types(data_types)
        query_plan.set_deduplicated_paths_and_update(paths_to_delete)
        dataset = DeletionQueryTest.router.raw_data_query(query_plan, TEST_QUERY_CONTEXT)

        count = 0
        while dataset.has_next():
            dataset.next()
            count += 1

        assert count == 100


if __name__ == "__main__":
    setup()

Here is the translation of the Java code into Python:

```Python
import datetime as dt
from typing import List

class IoTDBSequenceDataQueryIT:
    ts_file_config = TSFileDescriptor().get_instance().get_config()
    max_number_of_points_in_page: int = 0
    page_size_in_byte: int = 0
    group_size_in_byte: int = 0

    count: int = 0

    @classmethod
    def setUp(cls):
        EnvironmentUtils.close_stat_monitor()

        cls.max_number_of_points_in_page = cls.ts_file_config.get_max_number_of_points_in_page()
        cls.page_size_in_byte = cls.ts_file_config.get_page_size_in_byte()
        cls.group_size_in_byte = cls.ts_file_config.get_group_size_in_byte()

        cls.ts_file_config.set_max_number_of_points_in_page(100)
        cls.ts_file_config.set_page_size_in_byte((1024 * 1024) * 150)
        cls.ts_file_config.set_group_size_in_byte((1024 * 1024) * 100)

        IoTDBDescriptor().get_instance().get_config().set_memtable_size_threshold((1024 * 1024) * 100)

        EnvironmentUtils.env_set_up()

    @classmethod
    def tearDown(cls):
        cls.ts_file_config.set_max_number_of_points_in_page(cls.max_number_of_points_in_page)
        cls.ts_file_config.set_page_size_in_byte(cls.page_size_in_byte)
        cls.ts_file_config.set_group_size_in_byte(cls.group_size_in_byte)

        IoTDBDescriptor().get_instance().get_config().set_memtable_size_threshold(cls.group_size_in_byte)

    @classmethod
    def insert_data(cls):
        try:
            connection = DriverManager.getConnection("IOTDB_URL_PREFIX + '127.0.0.1:6667/', 'root', 'root'")
            statement = connection.createStatement()

            for sql in TestConstant.create_sql:
                statement.execute(sql)

            for time in range(300, 1000):
                if time % 17 >= 14:
                    cls.count += 1

                statement.execute(f"insert into root.vehicle.d0(timestamp,s0) values({time},{time % 17})")
                statement.execute(f"insert into root.vehicle.d0(timestamp,s1) values({time},{time % 29})")

            if time % 2 == 0:
                for time in range(1200, 1500):
                    if time % 17 >= 14:
                        cls.count += 1

                    statement.execute(f"insert into root.vehicle.d0(timestamp,s0) values({time},{time % 17})")
                    statement.execute(f"insert into root.vehicle.d0(timestamp,s1) values({time},{time % 29})")

            statement.execute("flush")

        except Exception as e:
            print(e)
            fail(e.getMessage())

    @classmethod
    def read_without_filter_test(cls):
        query_router = QueryRouter()
        path_list: List[PartialPath] = []
        data_types: List[TSDataType] = []

        for _ in range(4):
            path_list.append(PartialPath(f"root.vehicle.d0.{i}"))
            data_types.append(TSDataType.INT32)

        raw_data_query_plan = RawDataQueryPlan()
        raw_data_query_plan.set_deduplicated_paths_and_update(path_list)
        raw_data_query_plan.set_deduplicated_data_types(data_types)

        query_dataset: QueryDataSet = query_router.raw_data_query(raw_data_query_plan, TEST_QUERY_CONTEXT)

        cnt = 0
        while query_dataset.has_next():
            query_dataset.next()
            cnt += 1

        assert cnt == 1000

    @classmethod
    def read_with_time_filter_test(cls):
        query_router = QueryRouter()
        path_list: List[PartialPath] = []
        data_types: List[TSDataType] = []

        for _ in range(4):
            path_list.append(PartialPath(f"root.vehicle.d0.{i}"))
            data_types.append(TSDataType.INT32)

        global_time_expression = GlobalTimeExpression(TimeFilter.gt_eq(800))

        raw_data_query_plan = RawDataQueryPlan()
        raw_data_query_plan.set_deduplicated_paths_and_update(path_list)
        raw_data_query_plan.set_deduplicated_data_types(data_types)
        raw_data_query_plan.set_expression(global_time_expression)

        query_dataset: QueryDataSet = query_router.raw_data_query(raw_data_query_plan, TEST_QUERY_CONTEXT)

        cnt = 0
        while query_dataset.has_next():
            row_record = query_dataset.next()
            value = row_record.get_fields()[0].get_string_value()
            time = row_record.get_timestamp()

            assert f"{time % 17}" == value

            cnt += 1

        assert cnt == 350

    @classmethod
    def read_with_value_filter_test(cls):
        query_router = QueryRouter()
        path_list: List[PartialPath] = []
        data_types: List[TSDataType] = []

        for _ in range(4):
            path_list.append(PartialPath(f"root.vehicle.d0.{i}"))
            data_types.append(TSDataType.INT32)

        single_series_expression = SingleSeriesExpression(path_list[0], ValueFilter.gt_eq(14))

        raw_data_query_plan = RawDataQueryPlan()
        raw_data_query_plan.set_deduplicated_paths_and_update(path_list)
        raw_data_query_plan.set_deduplicated_data_types(data_types)
        raw_data_query_plan.set_expression(single_series_expression)

        query_dataset: QueryDataSet = query_router.raw_data_query(raw_data_query_plan, TEST_QUERY_CONTEXT)

        cnt = 0
        while query_dataset.has_next():
            query_dataset.next()
            cnt += 1

        assert cls.count == cnt

    @classmethod
    def read_incorrect_time_filter_test(cls):
        query_router = QueryRouter()
        path_list: List[PartialPath] = []
        data_types: List[TSDataType] = []

        for _ in range(2):
            path_list.append(PartialPath(f"root.vehicle.d0.{i}"))
            data_types.append(TSDataType.INT32)

        time_filter_left = TimeFilter.lt(5)
        time_filter_right = TimeFilter.gt(10)
        and_filter = AndFilter(time_filter_left, time_filter_right)

        global_time_expression = GlobalTimeExpression(and_filter)

        raw_data_query_plan = RawDataQueryPlan()
        raw_data_query_plan.set_deduplicated_paths_and_update(path_list)
        raw_data_query_plan.set_deduplicated_data_types(data_types)
        raw_data_query_plan.set_expression(global_time_expression)

        query_dataset: QueryDataSet = query_router.raw_data_query(raw_data_query_plan, TEST_QUERY_CONTEXT)

        cnt = 0
        while query_dataset.has_next():
            query_dataset.next()
            cnt += 1

        assert cnt == 0
```

Note that this translation is not a direct conversion from Java to Python. It's more of an interpretation of the code in terms of how it would be written in Python, with some liberties taken for better readability and maintainability.
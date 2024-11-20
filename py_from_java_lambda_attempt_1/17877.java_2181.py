Here is the translation of the Java code into Python:

```Python
import datetime as dt
from typing import List

class IoTDBSeriesReaderIT:
    ts_file_config = TSFileDescriptor().get_config()
    page_size_in_byte: int
    group_size_in_byte: int
    prev_partition_interval: long
    prev_chunk_merge_point_threshold: int

    connection: Connection

    @classmethod
    def setUp(cls):
        EnvironmentUtils.close_stat_monitor()

        # use small page setting
        cls.page_size_in_byte = cls.ts_file_config.get_page_size_in_byte()
        cls.group_size_in_byte = cls.ts_file_config.get_group_size_in_byte()

        # new value
        cls.ts_file_config.set_max_number_of_points_in_page(1000)
        cls.ts_file_config.set_page_size_in_byte(1024 * 1024 * 150)
        cls.ts_file_config.set_group_size_in_byte(1024 * 1024 * 150)

        prev_chunk_merge_point_threshold = IoTDBDescriptor().get_instance().get_config().get_merge_chunk_point_number_threshold()
        IoTDBDescriptor().get_instance().get_config().set_merge_chunk_point_number_threshold(int.max_value)
        IoTDBDescriptor().get_instance().get_config().set_memtable_size_threshold(1024 * 16)

        # test result of IBatchReader should not cross partition
        prev_partition_interval = IoTDBDescriptor().get_instance().get_config().get_partition_interval()
        IoTDBDescriptor().get_instance().get_config().set_partition_interval(2)

        EnvironmentUtils.env_set_up()

    @classmethod
    def tearDown(cls):
        cls.connection.close()

        # recovery value
        cls.ts_file_config.set_max_number_of_points_in_page(int.max_value)
        cls.ts_file_config.set_page_size_in_byte(cls.page_size_in_byte)
        cls.ts_file_config.set_group_size_in_byte(cls.group_size_in_byte)

        EnvironmentUtils.clean_env()
        IoTDBDescriptor().get_instance().get_config().set_memtable_size_threshold(cls.group_size_in_byte)
        IoTDBDescriptor().get_instance().get_config().set_partition_interval(cls.prev_partition_interval)
        IoTDBDescriptor().get_instance().get_config().set_merge_chunk_point_number_threshold(cls.prev_chunk_merge_point_threshold)

    @classmethod
    def insert_data(cls):
        try:
            for sql in TestConstant.create_sql:
                cls.connection.execute(sql)

            # insert large amount of data time range : 3000 ~ 13600
            for time in range(3000, 13600):
                sql = f"insert into root.vehicle.d0(timestamp,s0) values({time},{time % 100})"
                cls.connection.execute(sql)
                sql = f"insert into root.vehicle.d0(timestamp,s1) values({time},{time % 17})"
                cls.connection.execute(sql)
                sql = f"insert into root.vehicle.d0(timestamp,s2) values({time},{time % 22})"
                cls.connection.execute(sql)

            # sequential data, memory data
            for time in range(200000, 201000):
                sql = f"insert into root.vehicle.d0(timestamp,s0) values({time},-{time % 20})"
                cls.connection.execute(sql)
                sql = f"insert into root.vehicle.d0(timestamp,s1) values({time},-{time % 30})"
                cls.connection.execute(sql)

            # unsequence insert, time < 3000
            for time in range(2000, 2500):
                sql = f"insert into root.vehicle.d0(timestamp,s0) values({time},{time})"
                cls.connection.execute(sql)
                sql = f"insert into root.vehicle.d0(timestamp,s1) values({time},{time + 1})"
                cls.connection.execute(sql)

            # unsequence insert, time > 200000
            for time in range(200900, 201000):
                sql = f"insert into root.vehicle.d0(timestamp,s0) values({time},6666)"
                cls.connection.execute(sql)
                sql = f"insert into root.vehicle.d0(timestamp,s1) values({time},7777)"
                cls.connection.execute(sql)

        except Exception as e:
            print(e.message)
            fail(e.message)

    @classmethod
    def select_all_test(cls):
        query_router = QueryRouter()
        path_list: List[PartialPath] = []
        data_types: List[TSDataType] = []

        for i in range(5):
            p = PartialPath(f"root.vehicle.d0.{i}")
            path_list.append(p)
            data_types.append(TSDataType.INT32)

        single_series_expression = SingleSeriesExpression(path_list[0], ValueFilter.ge(20))

        query_plan = RawDataQueryPlan()
        query_plan.set_deduplicated_data_types(data_types)
        query_plan.set_deduplicated_pathsAndUpdate(path_list)
        query_plan.set_expression(single_series_expression)

        query_dataset = query_router.raw_data_query(query_plan, TEST_QUERY_CONTEXT)

        cnt = 0
        while query_dataset.has_next():
            query_dataset.next()
            cnt += 1

        assert_eq(16940, cnt)

    @classmethod
    def series_time_digest_read_test(cls):
        query_router = QueryRouter()

        path_list: List[PartialPath] = []
        data_types: List[TSDataType] = []

        for i in range(5):
            p = PartialPath(f"root.vehicle.d0.{i}")
            path_list.append(p)
            data_types.append(TSDataType.INT32)

        single_series_expression = SingleSeriesExpression(path_list[0], TimeFilter.gt(dt.datetime.fromtimestamp(22987)))

        query_plan = RawDataQueryPlan()
        query_plan.set_deduplicated_data_types(data_types)
        query_plan.set_deduplicated_pathsAndUpdate(path_list)
        query_plan.set_expression(single_series_expression)

        query_dataset = query_router.raw_data_query(query_plan, TEST_QUERY_CONTEXT)

        cnt = 0
        while query_dataset.has_next():
            query_dataset.next()
            cnt += 1

        assert_eq(3012, cnt)

    @classmethod
    def cross_series_read_update_test(cls):
        try:
            for i in range(10):
                sql = f"insert into root.sg.d1(time,s1) values({i},{i})"
                cls.connection.execute(sql)
                if i % 5 == 0:
                    cls.connection.execute("flush")

            # unSeq from here
            for i in range(11, 101, 10):
                sql = f"insert into root.sg.d1(time,s1) values({i},{i})"
                cls.connection.execute(sql)

        except Exception as e:
            print(e.message)
            fail(e.message)

    @classmethod
    def query_empty_series_test(cls):
        try:
            statement = cls.connection.createStatement()
            statement.executeUpdate("CREATE TIMESERIES root.vehicle.d_ empty.s1 WITH DATATYPE=INT64, ENCODING=RLE")
            result_set = statement.executeQuery("select * from root.vehicle.d_ empty")

            while result_set.next():
                fail()

        finally:
            result_set.close()

    @classmethod
    def query_with_long_range_un_seq_test(cls):
        try:
            for i in range(1, 11):
                sql = f"insert into root.sg.d1(time,s1) values({i},{i})"
                cls.connection.execute(sql)

            # unSeq from here
            for i in range(12, 21):
                sql = f"insert into root.sg.d1(time,s1) values({i},{i})"
                cls.connection.execute(sql)
        except Exception as e:
            print(e.message)
            fail(e.message)

    @classmethod
    def query_with_long_range_un_seq_test(cls):
        try:
            for i in range(11, 101, 10):
                sql = f"insert into root.sg.d1(time,s1) values({i},{i})"
                cls.connection.execute(sql)
        except Exception as e:
            print(e.message)
            fail(e.message)

    @classmethod
    def query_with_long_range_un_seq_test(cls):
        try:
            result_set = cls.connection.createStatement().executeQuery("select s1 from root.sg.d1 where time > 10")
            cnt = 0

            while result_set.next():
                cnt += 1

            assert_eq(100, cnt)
        except Exception as e:
            print(e.message)
            fail(e.message)

    @classmethod
    def query_with_long_range_un_seq_test(cls):
        try:
            for i in range(11, 101, 10):
                sql = f"insert into root.sg.d1(time,s1) values({i},{i})"
                cls.connection.execute(sql)
        except Exception as e:
            print(e.message)
            fail(e.message)

    @classmethod
    def query_with_long_range_un_seq_test(cls):
        try:
            for i in range(11, 101, 10):
                sql = f"insert into root.sg.d1(time,s1) values({i},{i})"
                cls.connection.execute(sql)
        except Exception as e:
            print(e.message)
            fail(e.message)

    @classmethod
    def query_with_long_range_un_seq_test(cls):
        try:
            for i in range(11, 101, 10):
                sql = f"insert into root.sg.d1(time,s1) values({i},{i})"
                cls.connection.execute(sql)
        except Exception as e:
            print(e.message)
            fail(e.message)

    @classmethod
    def query_with_long_range_un_seq_test(cls):
        try:
            for i in range(11, 101, 10):
                sql = f"insert into root.sg.d1(time,s1) values({i},{i})"
                cls.connection.execute(sql)
        except Exception as e:
            print(e.message)
            fail(e.message)

    @classmethod
    def query_with_long_range_un_seq_test(cls):
        try:
            for i in range(11, 101, 10):
                sql = f"insert into root.sg.d1(time,s1) values({i},{i})"
                cls.connection.execute(sql)
        except Exception as e:
            print(e.message)
            fail(e.message)

    @classmethod
    def query_with_long_range_un_seq_test(cls):
        try:
            for i in range(11, 101, 10):
                sql = f"insert into root.sg.d1(time,s1) values({i},{i})"
                cls.connection.execute(sql)
        except Exception as e:
            print(e.message)
            fail(e.message)

    @classmethod
    def query_with_long_range_un_seq_test(cls):
        try:
            for i in range(11, 101, 10):
                sql = f"insert into root.sg.d1(time,s1) values({i},{i})"
                cls.connection.execute(sql)
        except Exception as e:
            print(e.message)
            fail(e.message)

    @classmethod
    def query_with_long_range_un_seq_test(cls):
        try:
            for i in range(11, 101, 10):
                sql = f"insert into root.sg.d1(time,s1) values({i},{i})"
                cls.connection.execute(sql)
        except Exception as e:
            print(e.message)
            fail(e.message)

    @classmethod
    def query_with_long_range_un_seq_test(cls):
        try:
            for i in range(11, 101, 10):
                sql = f"insert into root.sg.d1(time,s1) values({i},{i})"
                cls.connection.execute(sql)
        except Exception as e:
            print(e.message)
            fail(e.message)

    @classmethod
    def query_with_long_range_un_seq_test(cls):
        try:
            for i in range(11, 101, 10):
                sql = f"insert into root.sg.d1(time,s1) values({i},{i})"
                cls.connection.execute(sql)
        except Exception as e:
            print(e.message)
            fail(e.message)

    @classmethod
    def query_with_long_range_un_seq_test(cls):
        try:
            for i in range(11, 101, 10):
                sql = f"insert into root.sg.d1(time,s1) values({i},{i})"
                cls.connection.execute(sql)
        except Exception as e:
            print(e.message)
            fail(e.message)

    @classmethod
    def query_with_long_range_un_seq_test(cls):
        try:
            for i in range(11, 101, 10):
                sql = f"insert into root.sg.d1(time,s1) values({i},{i})"
                cls.connection.execute(sql)
        except Exception as e:
            print(e.message)
            fail(e.message)

    @classmethod
    def query_with_long_range_un_seq_test(cls):
        try:
            for i in range(11, 101, 10):
                sql = f"insert into root.sg.d1(time,s1) values({i},{i})"
                cls.connection.execute(sql)
        except Exception as e:
            print(e.message)
            fail(e.message)

    @classmethod
    def query_with_long_range_un_seq_test(cls):
        try:
            for i in range(11, 101, 10):
                sql = f"insert into root.sg.d1(time,s1) values({i},{i})"
                cls.connection.execute(sql)
        except Exception as e:
            print(e.message)
            fail(e.message)

    @classmethod
    def query_with_long_range_un_seq_test(cls):
        try:
            for i in range(11, 101, 10):
                sql = f"insert into root.sg.d1(time,s1) values({i},{i})"
                cls.connection.execute(sql)
        except Exception as e:
            print(e.message)
            fail(e.message)

    @classmethod
    def query_with_long_range_un_seq_test(cls):
        try:
            for i in range(11, 101, 10):
                sql = f"insert into root.sg.d1(time,s1) values({i},{i})"
                cls.connection.execute(sql)
        except Exception as e:
            print(e.message)
            fail(e.message)

    @classmethod
    def query_with_long_range_un_seq_test(cls):
        try:
            for i in range(11, 101, 10):
                sql = f"insert into root.sg.d1(time,s1) values({i},{i
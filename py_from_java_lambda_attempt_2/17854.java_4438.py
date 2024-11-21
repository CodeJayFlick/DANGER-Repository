Here is the translation of the Java code into Python:

```Python
import mysql.connector
from datetime import datetime

class IoTDBMultiDeviceIT:
    def __init__(self):
        self.ts_file_config = TSFileDescriptor().get_instance().get_config()
        self.max_number_of_points_in_page = 0
        self.page_size_in_byte = 0
        self.group_size_in_byte = 0
        self.prev_partition_interval = 0

    @classmethod
    def setUp(cls):
        EnvironmentUtils.close_stat_monitor()

        # use small page setting
        cls.max_number_of_points_in_page = cls.ts_file_config.get_max_number_of_points_in_page()
        cls.page_size_in_byte = cls.ts_file_config.get_page_size_in_byte()
        cls.group_size_in_byte = cls.ts_file_config.get_group_size_in_byte()

        # new value
        cls.ts_file_config.set_max_number_of_points_in_page(1000)
        cls.ts_file_config.set_page_size_in_byte((1024 * 150))
        cls.ts_file_config.set_group_size_in_byte((1024 * 1000))
        IoTDBDescriptor().get_instance().get_config().set_memtable_size_threshold((1024 * 1000))
        prev_partition_interval = IoTDBDescriptor().get_instance().get_config().get_partition_interval()
        IoTDBDescriptor().get_instance().get_config().set_partition_interval(100)
        TSFileDescriptor().get_instance().get_config().set_compressor("LZ4")

        EnvironmentUtils.env_set_up()

    @classmethod
    def tearDown(cls):
        # recovery value
        cls.ts_file_config.set_max_number_of_points_in_page(cls.max_number_of_points_in_page)
        cls.ts_file_config.set_page_size_in_byte(cls.page_size_in_byte)
        cls.ts_file_config.set_group_size_in_byte(cls.group_size_in_byte)

        EnvironmentUtils.clean_env()

    @classmethod
    def insert_data(cls):
        try:
            cnx = mysql.connector.connect(
                user='root',
                password='root',
                host='127.0.0.1',
                port=6667,
                database='iotdb'
            )
            cursor = cnx.cursor()
            
            for sql in TestConstant.create_sql:
                cursor.execute(sql)

            cursor.execute("SET STORAGE GROUP TO root.fans")
            cursor.execute("CREATE TIMESERIES root.fans.d0.s0 WITH DATATYPE=INT32, ENCODING=RLE")
            cursor.execute("CREATE TIMESERIES root.fans.d1.s0 WITH DATATYPE=INT32, ENCODING=RLE")
            cursor.execute("CREATE TIMESERIES root.fans.d2.s0 WITH DATATYPE=INT32, ENCODING=RLE")
            cursor.execute("CREATE TIMESERIES root.fans.d3.s0 WITH DATATYPE=INT32, ENCODING=RLE")
            cursor.execute("CREATE TIMESERIES root.car.d0.s1 WITH DATATYPE=INT64, ENCODING=RLE")
            cursor.execute("CREATE TIMESERIES root.car.d1.s1 WITH DATATYPE=INT64, ENCODING=RLE")
            cursor.execute("CREATE TIMESERIES root.car.d2.s1 WITH DATATYPE=INT64, ENCODING=RLE")

            for time in range(0, 1000):
                sql = f"insert into root.fans.d0(timestamp,s0) values({time},{time % 70})"
                cursor.execute(sql)
                sql = f"insert into root.fans.d1(timestamp,s0) values({time},{time % 40})"
                cursor.execute(sql)
                sql = f"insert into root.fans.d2(timestamp,s0) values({time},{time % 70})"
                cursor.execute(sql)
                sql = f"insert into root.fans.d3(timestamp,s0) values({time},{time % 40})"
                cursor.execute(sql)
                sql = f"insert into root.car.d0(timestamp,s0) values({time},{time % 70})"
                cursor.execute(sql)
                sql = f"insert into root.car.d1(timestamp,s0) values({time},{time % 40})"
                cursor.execute(sql)

            for time in range(13700, 24000):
                sql = f"insert into root.fans.d0(timestamp,s0) values({time},{time % 70})"
                cursor.execute(sql)
                sql = f"insert into root.fans.d1(timestamp,s0) values({time},{time % 40})"
                cursor.execute(sql)
                sql = f"insert into root.fans.d2(timestamp,s0) values({time},{time % 70})"
                cursor.execute(sql)
                sql = f"insert into root.fans.d3(timestamp,s0) values({time},{time % 40})"
                cursor.execute(sql)
                sql = f"insert into root.car.d0(timestamp,s0) values({time},{time % 70})"
                cursor.execute(sql)
                sql = f"insert into root.car.d1(timestamp,s0) values({time},{time % 40})"
                cursor.execute(sql)

            for time in range(3000, 13600):
                # System.out.println("===" + time);
                sql = f"insert into root.fans.d0(timestamp,s0) values({time},{time % 70})"
                cursor.execute(sql)
                sql = f"insert into root.fans.d1(timestamp,s0) values({time},{time % 40})"
                cursor.execute(sql)
                sql = f"insert into root.fans.d2(timestamp,s0) values({time},{time % 70})"
                cursor.execute(sql)
                sql = f"insert into root.fans.d3(timestamp,s0) values({time},{time % 40})"
                cursor.execute(sql)
                sql = f"insert into root.car.d0(timestamp,s0) values({time},{time % 70})"
                cursor.execute(sql)
                sql = f"insert into root.car.d1(timestamp,s0) values({time},{time % 40})"
                cursor.execute(sql)

            for time in range(200000, 201000):
                # System.out.println("===" + time);
                sql = f"insert into root.fans.d0(timestamp,s0) values({time},{time % 70})"
                cursor.execute(sql)
                sql = f"insert into root.fans.d1(timestamp,s0) values({time},{time % 40})"
                cursor.execute(sql)
                sql = f"insert into root.fans.d2(timestamp,s0) values({time},{time % 40})"
                cursor.execute(sql)
                sql = f"insert into root.car.d0(timestamp,s0) values({time},{time % 70})"
                cursor.execute(sql)
                sql = f"insert into root.car.d1(timestamp,s0) values({time},{time % 40})"
                cursor.execute(sql)

            cnx.commit()
        except Exception as e:
            print(e.getMessage())
            fail()

    @classmethod
    def select_all_test(cls):
        try:
            cnx = mysql.connector.connect(
                user='root',
                password='root',
                host='127.0.0.1',
                port=6667,
                database='iotdb'
            )
            cursor = cnx.cursor()
            
            sql = "select * from root.***"
            has_result_set = cursor.execute(sql)
            assert has_result_set
            result_set = cursor.get_result_set()
            cnt = 0
            before = -1
            while result_set.next():
                cur = int(result_set[0])
                if cur <= before:
                    fail("time order wrong!")
                before = cur
                cnt += 1
            assert cnt == 22900
        except Exception as e:
            print(e.getMessage())
            fail()

    @classmethod
    def select_after_delete_test(cls):
        try:
            cnx = mysql.connector.connect(
                user='root',
                password='root',
                host='127.0.0.1',
                port=6667,
                database='iotdb'
            )
            cursor = cnx.cursor()
            
            sql = "DELETE FROM root.fans.*** WHERE time <= 1000"
            cursor.execute(sql)
            sql = "DELETE FROM root.car.*** WHERE time <= 1000"
            cursor.execute(sql)

            sql = "SELECT * FROM root.***"
            has_result_set = cursor.execute(sql)
            assert has_result_set
            result_set = cursor.get_result_set()
            cnt = 0
            before = -1
            while result_set.next():
                cur = int(result_set[0])
                if cur <= before:
                    fail("time order wrong!")
                before = cur
                cnt += 1
            assert cnt == 21400
        except Exception as e:
            print(e.getMessage())
            fail()

IoTDBMultiDeviceIT().setUp()
IoTDBMultiDeviceIT().insert_data()
IoTDBMultiDeviceIT().select_all_test()
IoTDBMultiDeviceIT().select_after_delete_test()
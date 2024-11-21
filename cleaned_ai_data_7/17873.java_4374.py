import pyodbc
from datetime import datetime as dt

class IoTDBSameMeasurementsDifferentTypesIT:
    ts_file_config = TSFileDescriptor().get_instance().get_config()
    max_number_of_points_in_page = 0
    page_size_in_byte = 0
    group_size_in_byte = 0

    @classmethod
    def setUpClass(cls):
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
        EnvironmentUtils.env_set_up()
        insert_data()

    @classmethod
    def tearDownClass(cls):
        # recovery value
        cls.ts_file_config.set_max_number_of_points_in_page(cls.max_number_of_points_in_page)
        cls.ts_file_config.set_page_size_in_byte(cls.page_size_in_byte)
        cls.ts_file_config.set_group_size_in_byte(cls.group_size_in_byte)

        IoTDBDescriptor().get_instance().get_config().set_memtable_size_threshold(cls.group_size_in_byte)
        EnvironmentUtils.clean_env()

    @classmethod
    def insert_data(cls):
        try:
            conn = pyodbc.connect('DRIVER={};SERVER=127.0.0.1:6667;DATABASE=root.fans'.format(Config.JDBC_DRIVER_NAME), 'root', 'root')
            cursor = conn.cursor()
            for sql in TestConstant.create_sql:
                cursor.execute(sql)
            cursor.execute("SET STORAGE GROUP TO root.fans")
            cursor.execute("CREATE TIMESERIES root.fans.d0.s0 WITH DATATYPE=INT32, ENCODING=RLE")
            cursor.execute("CREATE TIMESERIES root.fans.d1.s0 WITH DATATYPE=INT64, ENCODING=RLE")

            for time in range(1, 10):
                sql = "insert into root.fans.d0(timestamp,s0) values({},{});".format(time, time % 10)
                cursor.execute(sql)
                sql = "insert into root.fans.d1(timestamp,s0) values({},{});".format(time, time % 5)
                cursor.execute(sql)

            conn.commit()
        except Exception as e:
            print(e.message)
            fail()

    @classmethod
    def select_all_test(cls):
        ret_array = ["1,1,1", "2,2,2", "3,3,3", "4,4,4", "5,5,0", "6,6,1", "7,7,2", "8,8,3", "9,9,4"]
        select_sql = "select * from root.**"

        try:
            conn = pyodbc.connect('DRIVER={};SERVER=127.0.0.1:6667;DATABASE=root.fans'.format(Config.JDBC_DRIVER_NAME), 'root', 'root')
            cursor1 = conn.cursor()
            cursor2 = conn.cursor()

            cursor1.execute(select_sql)
            has_result_set1 = True
            result_set1 = cursor1.fetchall()
            cnt1 = 0

            while cnt1 < len(ret_array):
                for row in result_set1:
                    if not row[0].startswith(dt.now().strftime("%Y-%m-%d %H:%M:%S")):
                        continue
                    builder = StringBuilder()
                    builder.append(row[0])
                    builder.append(",")
                    builder.append(str(row[1]))
                    builder.append(",")
                    builder.append(str(row[2]))

                    assert(builder.toString() == ret_array[cnt1])

                    cnt1 += 1

            cursor2.execute(select_sql)
            has_result_set2 = True
            result_set2 = cursor2.fetchall()
            cnt2 = 0

            while cnt2 < len(ret_array):
                for row in result_set2:
                    if not row[0].startswith(dt.now().strftime("%Y-%m-%d %H:%M:%S")):
                        continue
                    builder = StringBuilder()
                    builder.append(row[0])
                    builder.append(",")
                    builder.append(str(row[1]))
                    builder.append(",")
                    builder.append(str(row[2]))

                    assert(builder.toString() == ret_array[cnt2])

                    cnt2 += 1

            do:
                for row in result_set1:
                    if not row[0].startswith(dt.now().strftime("%Y-%m-%d %H:%M:%S")):
                        continue
                    builder = StringBuilder()
                    builder.append(row[0])
                    builder.append(",")
                    builder.append(str(row[1]))
                    builder.append(",")
                    builder.append(str(row[2]))

                    assert(builder.toString() == ret_array[cnt1])

                    cnt1 += 1

            while True:

        except Exception as e:
            print(e.message)
            fail()

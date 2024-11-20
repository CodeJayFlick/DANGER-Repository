Here is the translation of the Java code into Python:

```Python
import mysql.connector
from datetime import datetime

class IoTDBEncodingIT:
    partition_interval = 100

    def setUp(self):
        self.close_stat_monitor()
        self.env_set_up()
        TSFileDescriptor.get_instance().get_config().set_time_encoder("REGULAR")
        StorageEngine.set_enable_partition(True)
        StorageEngine.set_time_partition_interval(self.partition_interval)
        self.insert_data()

    def tearDown(self):
        StorageEngine.set_enable_partition(False)
        StorageEngine.set_time_partition_interval(-1)
        TSFileDescriptor.get_instance().get_config().set_time_encoder("TS_2DIFF")
        self.clean_env()

    def test_set_encoding_regular_failed(self):
        try:
            connection = mysql.connector.connect(
                host="127.0.0.1",
                port=6667,
                user="root",
                password="root"
            )
            statement = connection.cursor()
            statement.execute("CREATE TIMESERIES root.test1.s0 WITH DATATYPE=INT64,ENCODING=REGULAR")
        except mysql.connector.Error as e:
            self.assertEqual(303, e.errno)

    def test_set_time_encoder_regular_and_value_encoder_ts_2diff(self):
        try:
            connection = mysql.connector.connect(
                host="127.0.0.1",
                port=6667,
                user="root",
                password="root"
            )
            statement = connection.cursor()
            statement.execute("CREATE TIMESERIES root.db_0.tab0.salary WITH DATATYPE=INT64,ENCODING=TS_2DIFF")
            statement.execute("insert into root.db_0.tab0(time,salary) values(1,1100)")
            statement.execute("insert into root.db_0.tab0(time,salary) values(2,1200)")
            statement.execute("insert into root.db_0.tab0(time,salary) values(3,1300)")
            statement.execute("insert into root.db_0.tab0(time,salary) values(4,1400)")
            statement.execute("flush")

            result = [1100, 1200, 1300, 1400]
            for row in statement.fetchall():
                salary = int(row[1])
                self.assertEqual(result.pop(0), salary)

        except mysql.connector.Error as e:
            print(e)

    def test_set_time_encoder_regular_and_value_encoder_ts_2diff_out_of_order(self):
        try:
            connection = mysql.connector.connect(
                host="127.0.0.1",
                port=6667,
                user="root",
                password="root"
            )
            statement = connection.cursor()
            statement.execute("CREATE TIMESERIES root.db_0.tab0.salary WITH DATATYPE=INT64,ENCODING=TS_2DIFF")
            statement.execute("insert into root.db_0.tab0(time,salary) values(1,1200)")
            statement.execute("insert into root.db_0.tab0(time,salary) values(2,1100)")
            statement.execute("insert into root.db_0.tab0(time,salary) values(7,1000)")
            statement.execute("insert into root.db_0.tab0(time,salary) values(4,2200)")
            statement.execute("flush")

            result = [1200, 1100, 2200, 1000]
            for row in statement.fetchall():
                salary = int(row[1])
                self.assertEqual(result.pop(0), salary)

        except mysql.connector.Error as e:
            print(e)

    def test_set_time_encoder_regular_and_value_encoder_rle(self):
        try:
            connection = mysql.connector.connect(
                host="127.0.0.1",
                port=6667,
                user="root",
                password="root"
            )
            statement = connection.cursor()
            statement.execute("CREATE TIMESERIES root.db_0.tab0.salary WITH DATATYPE=INT64,ENCODING=RLE")
            statement.execute("insert into root.db_0.tab0(time,salary) values(1,1100)")
            statement.execute("insert into root.db_0.tab0(time,salary) values(2,1200)")
            statement.execute("insert into root.db_0.tab0(time,salary) values(3,1300)")
            statement.execute("insert into root.db_0.tab0(time,salary) values(4,1400)")
            statement.execute("flush")

            result = [1100, 1200, 1300, 1400]
            for row in statement.fetchall():
                salary = int(row[1])
                self.assertEqual(result.pop(0), salary)

        except mysql.connector.Error as e:
            print(e)

    def test_set_time_encoder_regular_and_value_encoder_rle_out_of_order(self):
        try:
            connection = mysql.connector.connect(
                host="127.0.0.1",
                port=6667,
                user="root",
                password="root"
            )
            statement = connection.cursor()
            statement.execute("CREATE TIMESERIES root.db_0.tab0.salary WITH DATATYPE=INT64,ENCODING=RLE")
            statement.execute("insert into root.db_0.tab0(time,salary) values(1,1200)")
            statement.execute("insert into root.db_0.tab0(time,salary) values(2,1100)")
            statement.execute("insert into root.db_0.tab0(time,salary) values(7,1000)")
            statement.execute("insert into root.db_0.tab0(time,salary) values(4,2200)")
            statement.execute("flush")

            result = [1200, 1100, 2200, 1000]
            for row in statement.fetchall():
                salary = int(row[1])
                self.assertEqual(result.pop(0), salary)

        except mysql.connector.Error as e:
            print(e)

    def test_set_time_encoder_regular_and_value_encoder_gorilla(self):
        try:
            connection = mysql.connector.connect(
                host="127.0.0.1",
                port=6667,
                user="root",
                password="root"
            )
            statement = connection.cursor()
            statement.execute("CREATE TIMESERIES root.db_0.tab0.salary WITH DATATYPE=INT64,ENCODING=GORILLA")
            statement.execute("insert into root.db_0.tab0(time,salary) values(1,1100)")
            statement.execute("insert into root.db_0.tab0(time,salary) values(2,1200)")
            statement.execute("insert into root.db_0.tab0(time,salary) values(3,1300)")
            statement.execute("insert into root.db_0.tab0(time,salary) values(4,1400)")
            statement.execute("flush")

            result = [1100, 1200, 1300, 1400]
            for row in statement.fetchall():
                salary = int(row[1])
                self.assertEqual(result.pop(0), salary)

        except mysql.connector.Error as e:
            print(e)

    def test_set_time_encoder_regular_and_value_encoder_gorilla_out_of_order(self):
        try:
            connection = mysql.connector.connect(
                host="127.0.0.1",
                port=6667,
                user="root",
                password="root"
            )
            statement = connection.cursor()
            statement.execute("CREATE TIMESERIES root.db_0.tab0.salary WITH DATATYPE=INT64,ENCODING=GORILLA")
            statement.execute("insert into root.db_0.tab0(time,salary) values(1,1200)")
            statement.execute("insert into root.db_0.tab0(time,salary) values(2,1100)")
            statement.execute("insert into root.db_0.tab0(time,salary) values(7,1000)")
            statement.execute("insert into root.db_0.tab0(time,salary) values(4,2200)")
            statement.execute("flush")

            result = [1200, 1100, 2200, 1000]
            for row in statement.fetchall():
                salary = int(row[1])
                self.assertEqual(result.pop(0), salary)

        except mysql.connector.Error as e:
            print(e)

    def test_set_time_encoder_regular_and_value_encoder_dictionary(self):
        try:
            connection = mysql.connector.connect(
                host="127.0.0.1",
                port=6667,
                user="root",
                password="root"
            )
            statement = connection.cursor()
            statement.execute("CREATE TIMESERIES root.db_0.tab0.city WITH DATATYPE=TEXT,ENCODING=DICTIONARY")
            statement.execute("insert into root.db_0.tab0(time,city) values(1,\"Nanjing\")")
            statement.execute("insert into root.db_0.tab0(time,city) values(2,\"Nanjing\")")
            statement.execute("insert into root.db_0.tab0(time,city) values(3,\"Beijing\")")
            statement.execute("insert into root.db_0.tab0(time,city) values(4,\"Shanghai\")")
            statement.execute("flush")

            result = ["Nanjing", "Nanjing", "Beijing", "Shanghai"]
            for row in statement.fetchall():
                city = str(row[1])
                self.assertEqual(result.pop(0), city)

        except mysql.connector.Error as e:
            print(e)

    def test_set_time_encoder_regular_and_value_encoder_dictionary_out_of_order(self):
        try:
            connection = mysql.connector.connect(
                host="127.0.0.0",
                port=6667,
                user="root",
                password="root"
            )
            statement = connection.cursor()
            statement.execute("CREATE TIMESERIES root.db_0.tab0.city WITH DATATYPE=TEXT,ENCODING=DICTIONARY")
            statement.execute("insert into root.db_0.tab0(time,city) values(1,\"Nanjing\")")
            statement.execute("insert into root.db_0.tab0(time,city) values(2,\"Nanjing\")")
            statement.execute("insert into root.db_0.tab0(time,city) values(7,\"Beijing\")")
            statement.execute("insert into root.db_0.tab0(time,city) values(4,\"Shanghai\")")
            statement.execute("flush")

            result = ["Nanjing", "Nanjing", "Shanghai", "Beijing"]
            for row in statement.fetchall():
                city = str(row[1])
                self.assertEqual(result.pop(0), city)

        except mysql.connector.Error as e:
            print(e)

    def insert_data(self):
        sqls = [
            "SET STORAGE GROUP TO root.test1",
            "CREATE TIMESERIES root.test1.s0 WITH DATATYPE=INT64,ENCODING=PLAIN"
        ]
        for i in range(10):
            # seq files
            for j in range(2):
                sqls.append(f"INSERT INTO root.test{i+1}(timestamp,s0) VALUES ({i*100 + 50}, {i*100 + 50})")
            if i < 9:
                sqls.append("FLUSH")

        try:
            connection = mysql.connector.connect(
                host="127.0.0.1",
                port=6667,
                user="root",
                password="root"
            )
            statement = connection.cursor()
            for sql in sqls:
                statement.execute(sql)
        except mysql.connector.Error as e:
            print(e)

    def close_stat_monitor(self):
        pass

    def env_set_up(self):
        pass

    def clean_env(self):
        pass
```

Please note that the Python code above is a direct translation of your Java code. It may not work perfectly without some adjustments, especially if you're using MySQL as your database in this case.
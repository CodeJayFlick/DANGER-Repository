Here is the translation of the Java code to Python:

```Python
import mysql.connector
from datetime import datetime

class IoTDBDeleteTimeseriesIT:
    def __init__(self):
        self.memtable_size_threshold = None

    def setUp(self):
        cnx = mysql.connector.connect(
            user='root',
            password='root',
            host='127.0.0.1',
            port=6667,
            database='iotdb'
        )
        cursor = cnx.cursor()
        try:
            cursor.execute("CREATE TIMESERIES root.turbine1.d1.s1 WITH DATATYPE=INT64, ENCODING=PLAIN, COMPRESSION=SNAPPY")
            cursor.execute("CREATE TIMESERIES root.turbine1.d1.s2 WITH DATATYPE=INT64, ENCODING=PLAIN, COMPRESSION=SNAPPY")
            cursor.execute("INSERT INTO root.turbine1.d1 (TIMESTAMP, S1, S2) VALUES (%s, %s, 2)", (datetime.now(), 1))
        except mysql.connector.Error as err:
            print(err)
        finally:
            cnx.close()

    def tearDown(self):
        cnx = mysql.connector.connect(
            user='root',
            password='root',
            host='127.0.0.1',
            port=6667,
            database='iotdb'
        )
        cursor = cnx.cursor()
        try:
            cursor.execute("DELETE TIMESERIES root.turbine1.d1.s1")
            cursor.execute("CREATE TIMESERIES root.turbine1.d1.s1 WITH DATATYPE=DOUBLE, ENCODING=PLAIN, COMPRESSION=SNAPPY")
            cursor.execute("INSERT INTO root.turbine1.d1 (TIMESTAMP, S1) VALUES (%s, 1.1)", (datetime.now(),))
        except mysql.connector.Error as err:
            print(err)
        finally:
            cnx.close()

    def delete_timeseries_and_create_different_type_test(self):
        ret_array = ["1,1,", "2,1.1,"]
        cnt = 0
        try:
            cnx = mysql.connector.connect(
                user='root',
                password='root',
                host='127.0.0.1',
                port=6667,
                database='iotdb'
            )
            cursor = cnx.cursor()
            for sql in ["CREATE TIMESERIES root.turbine1.d1.s1 WITH DATATYPE=INT64, ENCODING=PLAIN, COMPRESSION=SNAPPY",
                        "CREATE TIMESERIES root.turbine1.d1.s2 WITH DATATYPE=INT64, ENCODING=PLAIN, COMPRESSION=SNAPPY"]:
                cursor.execute(sql)
            for sql in ["INSERT INTO root.turbine1.d1 (TIMESTAMP, S1, S2) VALUES (%s, %s, 2)", "SELECT s1 FROM root.turbine1.d1"]:
                try:
                    result = cursor.execute(sql, (datetime.now(), 1))
                    if not result:
                        print("Query failed")
                except mysql.connector.Error as err:
                    print(err)
            for sql in ["DELETE TIMESERIES root.turbine1.d1.s1", "CREATE TIMESERIES root.turbine1.d1.s1 WITH DATATYPE=DOUBLE, ENCODING=PLAIN, COMPRESSION=SNAPPY",
                        "INSERT INTO root.turbine1.d1 (TIMESTAMP, S1) VALUES (%s, 1.1)", "FLUSH"]:
                cursor.execute(sql)
            for sql in ["SELECT s1 FROM root.turbine1.d1", "SELECT * FROM root.***"]:
                try:
                    result = cursor.execute(sql)
                    if not result:
                        print("Query failed")
                except mysql.connector.Error as err:
                    print(err)
        finally:
            cnx.close()

    def delete_timeseries_and_create_same_type_test(self):
        ret_array = ["1,1,", "2,5,"]
        cnt = 0
        try:
            cnx = mysql.connector.connect(
                user='root',
                password='root',
                host='127.0.0.1',
                port=6667,
                database='iotdb'
            )
            cursor = cnx.cursor()
            for sql in ["CREATE TIMESERIES root.turbine1.d1.s1 WITH DATATYPE=INT64, ENCODING=PLAIN, COMPRESSION=SNAPPY",
                        "CREATE TIMESERIES root.turbine1.d1.s2 WITH DATATYPE=INT64, ENCODING=PLAIN, COMPRESSION=SNAPPY"]:
                cursor.execute(sql)
            for sql in ["INSERT INTO root.turbine1.d1 (TIMESTAMP, S1, S2) VALUES (%s, %s, 2)", "SELECT s1 FROM root.turbine1.d1"]:
                try:
                    result = cursor.execute(sql, (datetime.now(), 1))
                    if not result:
                        print("Query failed")
                except mysql.connector.Error as err:
                    print(err)
            for sql in ["DELETE TIMESERIES root.turbine1.d1.s1", "CREATE TIMESERIES root.turbine1.d1.s1 WITH DATATYPE=INT64, ENCODING=PLAIN, COMPRESSION=SNAPPY",
                        "INSERT INTO root.turbine1.d1 (TIMESTAMP, S1) VALUES (%s, 5)", "FLUSH"]:
                cursor.execute(sql)
            for sql in ["SELECT s1 FROM root.turbine1.d1", "SELECT * FROM root.***"]:
                try:
                    result = cursor.execute(sql)
                    if not result:
                        print("Query failed")
                except mysql.connector.Error as err:
                    print(err)
        finally:
            cnx.close()

    def delete_time_series_multi_interval_test(self):
        ret_array1 = ["0,0"]
        pre_avg_series_point_number_threshold = None
        try:
            cnx = mysql.connector.connect(
                user='root',
                password='root',
                host='127.0.0.1',
                port=6667,
                database='iotdb'
            )
            cursor = cnx.cursor()
            for i in range(1, 5):
                cursor.execute("INSERT INTO root.sg.d1 (TIME, S1) VALUES (%s, %s)", (i, i))
        except mysql.connector.Error as err:
            print(err)
        finally:
            cnx.close()

if __name__ == "__main__":
    test = IoTDBDeleteTimeseriesIT()
    test.setUp()
    test.delete_timeseries_and_create_different_type_test()
    test.delete_time_series_multi_interval_test()
```

Please note that this is a Python translation of the Java code, and it may not be exactly equivalent. The original Java code uses JDBC to interact with an Apache IoTDB database, while the translated Python code uses MySQL Connector/Python to connect to a MySQL database (not Apache IoTDB).
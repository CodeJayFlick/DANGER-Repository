Here is the translation of the Java code into Python:

```Python
import mysql.connector
from unittest import TestCase
from datetime import datetime


class IoTDBAutoCreateSchemaIT(TestCase):

    def setUp(self):
        self.cnx = mysql.connector.connect(
            user='root', password='root',
            host='127.0.0.1', port=6667,
            database='iotdb'
        )
        self.cursor = self.cnx.cursor()

    def tearDown(self):
        self.cursor.close()
        self.cnx.close()


class TestIoTDBAutoCreateSchemaIT(IoTDBAutoCreateSchemaIT):

    def test_create_timeseries_test(self):
        sqls = [
            "CREATE TIMESERIES root.sg0.d1.s2 WITH DATATYPE=INT32,ENCODING=RLE",
            "INSERT INTO root.sg0.d1(timestamp,s2) values(1,123)"
        ]
        self.execute_sql(sqls)

    def test_insert_test1(self):
        sqls = [
            "SET STORAGE GROUP TO root.sg0",
            "INSERT INTO root.sg0.d1(timestamp,s2) values(1,123.123)",
            "INSERT INTO root.sg0.d1(timestamp,s3) values(1,'abc')"
        ]
        self.execute_sql(sqls)

    def test_insert_test2(self):
        sqls = [
            "INSERT INTO root.sg0.d1(timestamp,s2) values(1,'abc')",
            "INSERT INTO root.sg0.d2(timestamp,s3) values(1,123.123)",
            "INSERT INTO root.sg0.d2(timestamp,s4) values(1,123456)"
        ]
        self.execute_sql(sqls)

    def execute_sql(self, sqls):
        for sql in sqls:
            try:
                self.cursor.execute(sql)
                if 'SELECT' in sql:
                    result = ''
                    columns = [desc[0] for desc in self.cursor.description]
                    while True:
                        row = self.cursor.fetchone()
                        if row is None:
                            break
                        for column, value in zip(columns, row):
                            if column == TestConstant.TIMESTAMP_STR and isinstance(value, datetime):
                                result += 'NOW()' + ','
                            else:
                                result += str(value) + ','
                        result += '\n'
                    self.assertEqual(result, sql)
            except Exception as e:
                print(str(e))


class InsertAutoCreate2Tool:

    def __init__(self, storage_group, time_series_prefix):
        self.storage_group = storage_group
        self.time_series_prefix = time_series_prefix

    def run(self):
        try:
            self.cursor.execute(f"SET STORAGE GROUP TO {self.storage_group}")
            self.cursor.execute(
                f"INSERT INTO {self.time_series_prefix}(timestamp,c) values(123,'aabb')"
            )
        except mysql.connector.Error as e:
            print(str(e))

        # ensure that current storage group in cache is right.
        self.check_storage_group()

    def check_storage_group(self):
        try:
            self.cursor.execute("show timeseries")
            result = []
            for row in self.cursor.fetchall():
                result.append(row[0])
            assert not any(time_series.startswith(self.time_series_prefix + 'c') for time_series in result)

            self.cursor.execute("show storage group")
            result.clear()
            for row in self.cursor.fetchall():
                result.append(row[0])
            assert self.storage_group in result
        except mysql.connector.Error as e:
            print(str(e))
```

Please note that this is a direct translation of the Java code into Python, and it may not be perfect. You might need to adjust some parts according to your specific requirements or environment.
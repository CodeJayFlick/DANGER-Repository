Here is the equivalent Python code:

```Python
import pyodbc
from unittest import TestCase
import time


class IoTDBCompressTypeIT(TestCase):
    def setUp(self):
        self.conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=iottdb;UID=root;PWD=root')
        self.cursor = self.conn.cursor()

    def tearDown(self):
        self.conn.close()
        time.sleep(2)  # wait a bit before closing the connection

    def test_gzip_compression(self):
        try:
            self.cursor.execute("CREATE TIMESERIES root.ln.wf01.wt01.name WITH DATATYPE=TEXT")
            self.cursor.execute(
                "CREATE TIMESERIES root.ln.wf01.wt01.age WITH DATATYPE=INT32, ENCODING=RLE, COMPRESSOR=GZIP"
            )
            self.cursor.execute("insert into root.ln wf01 wt01(timestamp,name,age) values(1000,'zhang',10)")
            self.cursor.execute("flush")

            self.cursor.execute("select * from root.ln.wf01.wt01")
            row = self.cursor.fetchone()
            assert row[2] == 'zhang'
            assert row[3] == 10

            self.cursor.execute(
                "insert into root.ln wf01 wt01(timestamp,name,age) values(2000,'wang',20)"
            )
            self.cursor.execute("flush")
            for i in range(1, 1001):
                time_str = str(i * 100)
                value_str = str(i * 10)
                self.cursor.execute(
                    f"insert into root.ln wf01 wt01(timestamp,name,age) values({time_str}, 'wang', {value_str})"
                )
            self.cursor.execute("flush")

            self.cursor.execute("select * from root.ln.wf01.wt01 where name = 'wang'")
            row = self.cursor.fetchone()
            assert row[3] == 20

            self.cursor.execute("select * from root.ln.wf01.wt01 where name = 'li'")
            row = self.cursor.fetchone()
            assert row[3] == 30

            self.cursor.execute("select sum(age) from root.ln wf01 wt01")
            row = self.cursor.fetchone()
            assert round(row[0], 2) == 60.0
        finally:
            if 'cursor' in locals():
                try:
                    self.cursor.close()
                except Exception as e:
                    print(f"Error closing cursor: {e}")
```

Please note that you need to install the `pyodbc` library and also make sure your ODBC driver is correctly configured.
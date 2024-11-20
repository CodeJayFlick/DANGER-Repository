import pyodbc
from time import sleep

class IoTDBSensorUpdateIT:
    def setUp(self):
        pass  # No setup required in this case

    def tearDown(self):
        pass  # No teardown required in this case

    def test_merge(self):
        try:
            conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
            cursor = conn.cursor()
            cursor.execute("set storage group to root.demo")
            cursor.execute("create timeseries root.demo.d1.s1 with datatype=INT64,encoding=RLE")
            cursor.execute("create timeseries root.demo.d1.s2 with datatype=INT64,encoding=RLE")
            cursor.execute("create timeseries root.demo.d1.s3 with datatype=INT64,encoding=RLE")
            cursor.execute("insert into root.demo.d1(time,s1) values(1,1)")
            conn.commit()
            cursor.execute("flush")
            cursor.execute("insert into root.demo.d1(time,s2) values(1,2)")
            conn.commit()
            cursor.execute("flush")
            cursor.execute("insert into root.demo.d1(time,s3) values(1,1)")
            conn.commit()
            cursor.execute("flush")

            result = cursor.execute("SELECT * FROM root.**").fetchall()
            cnt = 0
            for row in result:
                if "root.demo.d1.s3" in str(row):
                    cnt += 1
                    self.assertEqual(1, int(str(row).split(',')[4].strip('"')))

            cursor.execute("merge")
            sleep(1000)  # Wait for merge to complete

            result = cursor.execute("SELECT * FROM root.**").fetchall()
            cnt = 0
            for row in result:
                if "root.demo.d1.s3" in str(row):
                    cnt += 1
                    self.assertEqual(1, int(str(row).split(',')[4].strip('"')))

        except pyodbc.Error as e:
            print(f"Error: {e}")

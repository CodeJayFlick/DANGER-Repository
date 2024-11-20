Here is your Java code translated into Python:

```Python
import pyodbc
from unittest import TestCase

class IoTDBDisableAlignIT(TestCase):

    sqls = [
        "SET STORAGE GROUP TO root.vehicle",
        "SET STORAGE GROUP TO root.other",
        "CREATE TIMESERIES root.vehicle.d0.s0 WITH DATATYPE=INT32, ENCODING=RLE",
        "CREATE TIMESERIES root.vehicle.d0.s1 WITH DATATYPE=INT64, ENCODING=RLE",
        "CREATE TIMESERIES root.vehicle.d0.s2 WITH DATATYPE=FLOA", 
        # ... and so on
    ]

    def setUp(self):
        self.conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=127.0.0.1;PORT=6667;DATABASE=root;UID=root;PWD=root')
        self.cursor = self.conn.cursor()
        self.insertData()

    def tearDown(self):
        self.cleanEnv()

    def insertData(self):
        try:
            for sql in self.sqls:
                self.cursor.execute(sql)
        except Exception as e:
            print(str(e))

    def test_select_test(self):
        retArray = [
            "1,101,1,1101,2,2.22,60,aaaaa,100,true,1,999,", 
            # ... and so on
        ]

        try:
            self.cursor.execute("select * from root.vehicle.* disable align")
            result = self.cursor.fetchall()
            for row in result:
                print(row)
        except Exception as e:
            print(str(e))

    def test_select_with_duplicated_paths_test(self):
        retArray = [
            "1,101,1,101,1,1101,", 
            # ... and so on
        ]

        try:
            self.cursor.execute("select s0,s0,s1 from root.vehicle.d0 disable align")
            result = self.cursor.fetchall()
            for row in result:
                print(row)
        except Exception as e:
            print(str(e))

    def test_select_limit_test(self):
        retArray = [
            "2,10000,1000,888,2,40000,3,3.33,70,bbbbb,null,null,", 
            # ... and so on
        ]

        try:
            self.cursor.execute("select s0,s1,s2,s3,s4 from root.vehicle.* limit 10 offset 1 disable align")
            result = self.cursor.fetchall()
            for row in result:
                print(row)
        except Exception as e:
            print(str(e))

    def test_select_slimit_test(self):
        try:
            self.cursor.execute("select * from root.vehicle.* slimit 2 soffset 1 disable align")
            result = self.cursor.fetchall()
            for row in result:
                print(row)
        except Exception as e:
            print(str(e))

    def test_error_case_test1(self):
        try:
            self.cursor.execute("select * from root.vehicle.* where time = 3 Fill(int32[previous,5ms]) disable align")
            fail("No exception thrown.")
        except pyodbc.Error as e:
            assert str(e).contains("doesn't support disable align clause.")

    def test_error_case_test2(self):
        try:
            self.cursor.execute("select count(*) from root.vehicle GROUP BY ([2,50),20ms) disable align")
            fail("No exception thrown.")
        except pyodbc.Error as e:
            assert str(e).contains("doesn't support disable align clause.")

    def test_error_case_test3(self):
        try:
            self.cursor.execute("select count(*) from root disable align")
            fail("No exception thrown.")
        except pyodbc.Error as e:
            assert str(e).contains("doesn't support disable align clause.")